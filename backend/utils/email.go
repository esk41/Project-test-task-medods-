package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

func SendEmail(emailTo, subject, body string) error {
	emailFrom := os.Getenv("EMAIL_FROM")
	emailFromPassword := os.Getenv("EMAIL_FROM_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	message := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n%s",
		emailFrom, emailTo, subject, body,
	)

	auth := smtp.PlainAuth("", emailFrom, emailFromPassword, smtpHost)

	err := smtp.SendMail(
		smtpHost+":"+smtpPort,
		auth,
		emailFrom,
		[]string{emailTo},
		[]byte(message),
	)

	return err
}
