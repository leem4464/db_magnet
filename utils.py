import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(email_info, subject, email_text):
    # SMTP
    smtp = smtplib.SMTP(email_info['host'], email_info['port'])
    smtp.ehlo()
    smtp.starttls()
    smtp.login(email_info['account'], email_info['passwd'])

    email_text = MIMEText(email_text, _charset='utf-8')

    # send email
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['To'] = email_info['send_to']
    msg.attach(email_text)

    try:
        smtp.sendmail(email_info['account'], email_info['send_to'], msg.as_string())
        return True
    except Exception as e:
        print(e)
        return False
    finally:
        smtp.quit()


def make_email_text(data):
    subject = 'Find database results'

    email_text_list = []
    for d in data:
        for f in d:
            email_text = '''
IP : {}

Port : {}

App name: {}

App version: {}

Vulnerabilities : {}

Scanned time : {}
'''.format(
    f['ip'],
    f['open_port_no'],
    f['app_name'],
    f['app_version'],
    f['vuln'],
    f['confirmed_time'],
)

            email_text_list.append(email_text) 

    email_text = '\n------------------------------\n'.join(email_text_list)

    return subject, email_text
