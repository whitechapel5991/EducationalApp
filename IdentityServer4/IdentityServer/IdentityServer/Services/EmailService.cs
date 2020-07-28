using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer.Services
{
    public class EmailService
    {
        private readonly ILogger<EmailService> logger;

        public EmailService(ILogger<EmailService> logger)
        {
            this.logger = logger;
        }


        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var emailMessage = new MimeMessage(
                //new MailboxAddress("Администрация сайта", "whitechapel5991@gmail.com"), 
                //new MailboxAddress("",email),
                //subject,
                // new BodyBuilder() { HtmlBody = "<div style=\"color: green;\">" + message + "</div>" }.ToMessageBody()
                );

            emailMessage.From.Add(new MailboxAddress("Администрация сайта", "EducationalApp@yandex.by"));
            emailMessage.To.Add(new MailboxAddress("", email));
            emailMessage.Subject = subject;
            emailMessage.Body = new BodyBuilder() { HtmlBody = "<div style=\"color: green;\">" + message + "</div>" }.ToMessageBody();
            //new TextPart(MimeKit.Text.TextFormat.Html)
            //{
            //    Text = message
            //};

            using (var client = new SmtpClient())
            {
                await client.ConnectAsync("smtp.yandex.ru", 587, SecureSocketOptions.StartTls);
                await client.AuthenticateAsync("EducationalApp@yandex.by", "7752393LoL");
                await client.SendAsync(emailMessage);

                await client.DisconnectAsync(true);
                logger.LogInformation("Сообщение отправлено успешно!");
            }
        }

    }
}
