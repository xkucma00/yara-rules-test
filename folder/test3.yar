include "../test1.yar"
include "test2.yar"

rule A {
  strings: $s = "Welcome!"
  condition: contains_base64 or $s
}

rule B {
  condition: A or (not Prime_Constants_Long and maldoc_OLE_file_magic_number)
}
