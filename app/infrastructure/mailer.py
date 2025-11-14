import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from ..core.settings import settings


def send_email(to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> None:
    host = settings.SMTP_HOST
    port = settings.SMTP_PORT
    user = settings.SMTP_USER
    password = settings.SMTP_PASSWORD
    from_addr = settings.SMTP_FROM or user
    from_name = settings.SMTP_FROM_NAME

    if not (host and port and user and password):
        raise RuntimeError(
            "SMTP is not configured. Please set SMTP credentials via overrides in mailer.py or environment variables."
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    msg["To"] = to_email

    if text_body:
        msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        server.starttls()
        server.login(user, password)
        server.sendmail(from_addr, [to_email], msg.as_string())


def send_otp_email(to_email: str, code: str) -> None:
    subject = "Your OTP Code"
    html = f"""
    <p>Hello,</p>
    <p>Your one-time password (OTP) is:</p>
    <p style='font-size:20px;font-weight:bold;letter-spacing:2px'>{code}</p>
    <p>This code expires in a few minutes. If you did not request this, please ignore this email.</p>
    """
    text = f"Your OTP code is: {code}"
    send_email(to_email, subject, html, text)


def send_verification_email(to_email: str, code: str) -> None:
    subject = "Verify your account"
    html = f"""
    <p>Welcome!</p>
    <p>Use this code to verify your account:</p>
    <p style='font-size:20px;font-weight:bold;letter-spacing:2px'>{code}</p>
    <p>If you did not create an account, you can ignore this email.</p>
    """
    text = f"Your verification code is: {code}"
    send_email(to_email, subject, html, text)
