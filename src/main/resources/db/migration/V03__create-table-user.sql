CREATE TABLE `user` (
	id BIGINT NOT NULL AUTO_INCREMENT,
	name varchar (80) NOT NULL,
	email varchar(80) NOT NULL,
	password varchar(255) NOT NULL,
	active BOOLEAN NOT NULL DEFAULT true,

	PRIMARY KEY(id),
	UNIQUE KEY user_email_uk(email)
);

INSERT INTO `user` (name, email, password) VALUES ("João Embaixadinha", "joaoembaixadinha@login.system", "$2a$12$lKzyADi6iolo7WOpC/hF3eR1IU6vveUFt2epTlyLbq3CVfZ.CvfGW");
INSERT INTO `user` (name, email, password) VALUES ("Renato Rabisco", "renatorabisco@login.system", "$2a$12$lKzyADi6iolo7WOpC/hF3eR1IU6vveUFt2epTlyLbq3CVfZ.CvfGW");