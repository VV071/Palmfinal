const nodemailer = require('nodemailer');

async function sendTestEmail() {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'vishnuvardhanr.0207@gmail.com',      // Replace with your email user
      pass: 'natfbqrfarvxjrku',       // Replace with your email app password or normal password
    },
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 5000,
  });

  try {
    const info = await transporter.sendMail({
      from: '"Test Sender" <vishnuvaradhanr.0207@gmail.com>',  // sender address
      to: 'vishnur0207@gmail.com',                     // receiver address (can be your own)
      subject: 'SMTP Credentials Test',
      text: 'This is a test email using Nodemailer SMTP configuration.',
    });
    console.log('Test email sent:', info.messageId);
  } catch (error) {
    console.error('Failed to send test email:', error);
  }
}

sendTestEmail();
