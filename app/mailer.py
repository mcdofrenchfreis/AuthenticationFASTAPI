import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from .config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    SMTP_FROM,
    SMTP_FROM_NAME,
)


SMTP_HOST_OVERRIDE = "smtp.gmail.com"
SMTP_PORT_OVERRIDE = 587
SMTP_USER_OVERRIDE = "gagokayvan@gmail.com"
SMTP_PASSWORD_OVERRIDE = "pmdt pkeo mwab dyuo"
SMTP_FROM_OVERRIDE = "gagokayvan@gmail.com"
SMTP_FROM_NAME_OVERRIDE = "AUTH"


def send_email(to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> None:
    host = SMTP_HOST_OVERRIDE or SMTP_HOST
    port = SMTP_PORT_OVERRIDE if SMTP_PORT_OVERRIDE is not None else SMTP_PORT
    user = SMTP_USER_OVERRIDE or SMTP_USER
    password = SMTP_PASSWORD_OVERRIDE or SMTP_PASSWORD
    from_addr = SMTP_FROM_OVERRIDE or SMTP_FROM or user
    from_name = SMTP_FROM_NAME_OVERRIDE or SMTP_FROM_NAME

    if not (host and port and user and password):
        raise RuntimeError("SMTP is not configured. Please set SMTP credentials via overrides in mailer.py or environment variables.")

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
