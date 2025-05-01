# -*- encoding: utf-8 -*-

import io
import json
import smtplib
import socket
import time

from _thread import start_new_thread
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from string import Template
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import logging
logger = logging.getLogger("isso")

try:
    import uwsgi
except ImportError:
    uwsgi = None

from isso import dist, local
from isso.views.comments import isurl


def create_comment_action_url(uri, action, key):
    return uri + "/" + action + "/" + key


class SMTPConnection(object):

    def __init__(self, conf):
        self.conf = conf

    def __enter__(self):
        klass = (smtplib.SMTP_SSL if self.conf.get(
            'security') == 'ssl' else smtplib.SMTP)
        self.client = klass(host=self.conf.get('host'),
                            port=self.conf.getint('port'),
                            timeout=self.conf.getint('timeout'))

        if self.conf.get('security') == 'starttls':
            import ssl
            self.client.starttls(context=ssl.create_default_context())

        username = self.conf.get('username')
        password = self.conf.get('password')
        if username and password:
            self.client.login(username, password)

        return self.client

    def __exit__(self, exc_type, exc_value, traceback):
        self.client.quit()


class SMTP(object):

    def __init__(self, isso):

        self.isso = isso
        self.conf = isso.conf.section("smtp")
        self.public_endpoint = isso.conf.get("server", "public-endpoint") or local("host")
        self.admin_notify = any((n in ("smtp", "SMTP")) for n in isso.conf.getlist("general", "notify"))
        self.reply_notify = isso.conf.getboolean("general", "reply-notifications")

        # test SMTP connectivity
        try:
            with SMTPConnection(self.conf):
                logger.info("connected to SMTP server")
        except (socket.error, smtplib.SMTPException):
            logger.exception("unable to connect to SMTP server")

        if uwsgi:
            def spooler(args):
                try:
                    self._sendmail(args[b"subject"].decode("utf-8"),
                                   args["body"].decode("utf-8"),
                                   args[b"to"].decode("utf-8"),
                                   args[b"headers"].decode("utf-8"))
                except smtplib.SMTPConnectError:
                    return uwsgi.SPOOL_RETRY
                else:
                    return uwsgi.SPOOL_OK

            uwsgi.spooler = spooler

    def __iter__(self):
        yield "comments.new:after-save", self.notify_new
        yield "comments.activate", self.notify_activated

    # Add List-Unsubscribe email header
    def create_headers(self, parent_comment, recipient):
        uri = self.public_endpoint + "/id/%i" % parent_comment["id"]
        key = self.isso.sign(('unsubscribe', recipient))
        return (('List-Unsubscribe', uri + "/unsubscribe/" + quote(recipient) + "/" + key),)

    def format(self, thread, comment, parent_comment, recipient=None, admin=False):

        rv = io.StringIO()

        author = comment["author"] or "Anonymous"
        if admin and comment["email"]:
            author += " <%s>" % comment["email"]

        rv.write(author + " wrote:\n")
        rv.write("\n")
        rv.write(comment["text"] + "\n")
        rv.write("\n")

        if admin:
            if comment["website"]:
                rv.write("User's URL: %s\n" % comment["website"])

            rv.write("IP address: %s\n" % comment["remote_addr"])

        rv.write("Link to comment: %s\n" %
                 (local("origin") + thread["uri"] + "#isso-%i" % comment["id"]))
        rv.write("\n")
        rv.write("---\n")

        if admin:
            uri = self.public_endpoint + "/id/%i" % comment["id"]
            key = self.isso.sign(comment["id"])

            rv.write("Delete comment: %s\n" % create_comment_action_url(uri, "delete", key))

            if comment["mode"] == 2:
                rv.write("Activate comment: %s\n" % create_comment_action_url(uri, "activate", key))

        else:
            uri = self.public_endpoint + "/id/%i" % parent_comment["id"]
            key = self.isso.sign(('unsubscribe', recipient))

            rv.write("Unsubscribe from this conversation: %s\n" % (uri + "/unsubscribe/" + quote(recipient) + "/" + key))

        rv.seek(0)
        return rv.read()

    def notify_new(self, thread, comment):
        if self.admin_notify:
            body = self.format(thread, comment, None, admin=True)
            subject = "New comment posted"
            if thread['title']:
                subject = "%s on %s" % (subject, thread["title"])
            self.sendmail(subject, body, thread, comment, None)

        if comment["mode"] == 1:
            self.notify_users(thread, comment)

    def notify_activated(self, thread, comment):
        self.notify_users(thread, comment)

    def notify_users(self, thread, comment):
        if self.reply_notify and "parent" in comment and comment["parent"] is not None:
            # Notify interested authors that a new comment is posted
            notified = []
            parent_comment = self.isso.db.comments.get(comment["parent"])
            comments_to_notify = [parent_comment] if parent_comment is not None else []
            comments_to_notify += self.isso.db.comments.fetch(thread["uri"], mode=1, parent=comment["parent"])
            for comment_to_notify in comments_to_notify:
                email = comment_to_notify["email"]
                if "email" in comment_to_notify and comment_to_notify["notification"] and email not in notified \
                        and comment_to_notify["id"] != comment["id"] and email != comment["email"]:
                    body = self.format(thread, comment, parent_comment, email, admin=False)
                    headers = self.create_headers(parent_comment, email)
                    subject = "Re: New comment posted on %s" % thread["title"]
                    self.sendmail(subject, body, thread, comment, to=email, headers=headers)
                    notified.append(email)

    def sendmail(self, subject, body, thread, comment, to=None, headers=None):
        to = to or self.conf.get("to")
        if not subject:
            # Fallback, just in case as an empty subject does not work
            subject = 'isso notification'

        if uwsgi:
            if not headers:
                headers = ''
            uwsgi.spool({b"subject": subject.encode("utf-8"),
                         b"body": body.encode("utf-8"),
                         b"to": to.encode("utf-8"),
                         b"headers": headers.encode("utf-8")})
        else:
            start_new_thread(self._retry, (subject, body, to, headers))

    def _sendmail(self, subject, body, to_addr, headers=None):

        from_addr = self.conf.get("from")

        msg = EmailMessage()
        msg.set_payload(body, 'utf-8')
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject

        for key, val in headers if headers else ():
            msg.add_header(key, val)

        with SMTPConnection(self.conf) as con:
            con.send_message(msg, from_addr, to_addr)

    def _retry(self, subject, body, to, headers):
        for x in range(5):
            try:
                self._sendmail(subject, body, to, headers)
            except smtplib.SMTPConnectError:
                time.sleep(60)
            else:
                break


class Stdout(object):

    def __init__(self, isso):
        self.isso = isso
        self.public_endpoint = isso.conf.get("server", "public-endpoint") or local("host")

    def __iter__(self):

        yield "comments.new:new-thread", self._new_thread
        yield "comments.new:finish", self._new_comment
        yield "comments.edit", self._edit_comment
        yield "comments.delete", self._delete_comment
        yield "comments.activate", self._activate_comment

    def _new_thread(self, thread):
        logger.info("new thread %(id)s: %(title)s" % thread)

    def _new_comment(self, thread, comment):
        logger.info("comment created: %s", json.dumps(comment))
        logger.info("Link to comment: %s" % (local("origin") + thread["uri"] + "#isso-%i" % comment["id"]))

        uri = self.public_endpoint + "/id/%i" % comment["id"]
        key = self.isso.sign(comment["id"])

        logger.info("Delete comment: %s" % create_comment_action_url(uri, "delete", key))

        if comment["mode"] == 2:
            logger.info("Activate comment: %s" % create_comment_action_url(uri, "activate", key))

    def _edit_comment(self, comment):
        logger.info('comment %i edited: %s',
                    comment["id"], json.dumps(comment))

    def _delete_comment(self, id):
        logger.info('comment %i deleted', id)

    def _activate_comment(self, thread, comment):
        logger.info("comment %(id)s activated" % thread)


class Webhook(object):
    """Notification handler for webhooks.

    :param isso_instance: Isso application instance. Used to get moderation key.
    :type isso_instance: object

    :raises ValueError: if the provided URL is not valid
    :raises FileExistsError: if the provided JSON template doesn't exist
    :raises TypeError: if the provided template file is not a JSON
    """

    def __init__(self, isso_instance: object):
        """Instanciate class."""
        # store isso instance
        self.isso_instance = isso_instance
        # retrieve relevant configuration
        self.public_endpoint = isso_instance.conf.get(
            section="server", option="public-endpoint"
        ) or local("host")
        webhook_conf_section = isso_instance.conf.section("webhook")
        self.wh_url = webhook_conf_section.get("url")
        self.wh_template = webhook_conf_section.get("template")

        # check required settings
        if not isurl(self.wh_url):
            raise ValueError(
                "The webhook notification functionality requires a valid URL to work. "
                f"The provided one is not correct: {self.wh_url}"
            )

        # check optional template
        if not len(self.wh_template):
            self.wh_template = None
            logger.debug("No webhook template provided. Using default POST data for webhook requests")
        elif not Path(self.wh_template).is_file():
            raise FileExistsError(f"Invalid web hook template path: {self.wh_template}")
        elif not Path(self.wh_template).suffix.lower() == ".json":
            raise TypeError(f"Webhook template must be a JSON file with .json as file extension: {self.wh_template}")
        else:
            self.wh_template = Path(self.wh_template)

    def __iter__(self):

        yield "comments.new:after-save", self.new_comment

    def new_comment(self, thread: dict, comment: dict) -> bool:
        """Triggered when a new comment is saved.

        :param thread: comment thread
        :type thread: dict
        :param comment: comment object
        :type comment: dict

        :return: True if POST request succeeded, else False.
        :rtype: bool
        """

        try:
            moderation_urls = self.moderation_urls(thread, comment)

            if self.wh_template:
                post_data = self.render_template(thread, comment, moderation_urls)
            else:
                post_data = {
                    "author_name": comment.get("author", "Anonymous"),
                    "author_email": comment.get("email"),
                    "author_website": comment.get("website"),
                    "comment_ip_address": comment.get("remote_addr"),
                    "comment_text": comment.get("text"),
                    "comment_url_activate": moderation_urls[0],
                    "comment_url_delete": moderation_urls[1],
                    "comment_url_view": moderation_urls[2],
                }

            self.send(post_data)
        except Exception as err:
            logger.error(err)
            return False

        return True

    def moderation_urls(self, thread: dict, comment: dict) -> tuple:
        """Helper to build comment related URLs (deletion, activation, etc.).

        :param thread: comment thread
        :type thread: dict
        :param comment: comment object
        :type comment: dict

        :return: tuple of URS in alpha order (activate, delete, view)
        :rtype: tuple
        """
        uri = f"{self.public_endpoint}/id/{comment.get('id')}"
        key = self.isso_instance.sign(comment.get("id"))

        url_activate = f"{uri}/activate/{key}"
        url_delete = f"{uri}/delete/{key}"
        url_view = f"{local('origin')}{thread.get('uri')}#isso-{comment.get('id')}"

        return (url_activate, url_delete, url_view)

    def render_template(
        self, thread: dict, comment: dict, moderation_urls: tuple
    ) -> str:
        """Format comment information as webhook payload filling the specified template.

        :param thread: isso thread
        :type thread: dict
        :param comment: isso comment
        :type comment: dict
        :param moderation_urls: comment moderation URLs
        :type comment: tuple

        :return: formatted message from template
        :rtype: str
        """
        # load template
        with self.wh_template.open("r") as in_file:
            template_json_data = json.load(in_file)
        template_str = Template(json.dumps(template_json_data))

        # substitute
        return template_str.substitute(
            AUTHOR_NAME=comment.get("author", "Anonymous"),
            AUTHOR_EMAIL=f"<{comment.get('email', '')}>",
            AUTHOR_WEBSITE=comment.get("website", ""),
            COMMENT_IP_ADDRESS=comment.get("remote_addr"),
            COMMENT_TEXT=comment.get("text"),
            COMMENT_URL_ACTIVATE=moderation_urls[0],
            COMMENT_URL_DELETE=moderation_urls[1],
            COMMENT_URL_VIEW=moderation_urls[2],
        )

    def send(self, structured_msg: str) -> bool:
        """Send the structured message as a notification to the class webhook URL.

        :param structured_msg: structured message to send
        :type structured_msg: str

        :return: True if POST request succeeded, else False.
        :rtype: bool
        """
        # load the message to ensure encoding
        msg_json = json.loads(structured_msg)
        headers= {
            "Content-Type": "application/json;charset=utf-8",
            "User-Agent": f"Isso/{dist.version} (+https://posativ.org/isso)",
        }

        post_req = Request(
            method="POST",
            url=self.wh_url,
            data=json.dumps(msg_json).encode("utf-8"),
            headers=headers
        )

        try:
            urlopen(post_req, timeout=60)
            logger.info(f"Webhook request sent to {self.wh_url}")
            return True
        except HTTPError as exc:
            charset = exc.headers.get_content_charset() or "utf-8"
            response_body: str = exc.read().decode(charset)

            logger.error(f"Something went wrong during POST request to the webhook URL: {self.wh_url}. Trace: {response_body}")
            return False
