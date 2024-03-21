
drop table if exists `users`;

create table if not exists `users` (
  `id` int not null primary key auto_increment,
  `username` varchar(255) not null,
  `password` varchar(32) not null,
  `created_at` datetime default current_timestamp,
  `updated_at` datetime default null,
  `deleted_at` datetime default null
);

insert into `users` (`username`, `password`) values ('bob', MD5('secret'));
insert into `users` (`username`, `password`) values ('sue', MD5('secret'));
insert into `users` (`username`, `password`) values ('tom', MD5('secret'));
insert into `users` (`username`, `password`) values ('ted', MD5('secret'));
insert into `users` (`username`, `password`) values ('sam', MD5('secret'));
insert into `users` (`username`, `password`) values ('roy', MD5('secret'));
