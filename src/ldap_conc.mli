
module Id : Ldap_types.Monad with type 'a t = 'a

val readbyte_of_unix_fd : Unix.file_descr -> Id.readbyte
