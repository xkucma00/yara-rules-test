include "../test1.yar"
include "test2.yar"

rule A {
  strings: $s = "Welcome!"
  condition: Prime_Constants_long or $s or false
}

rule B {
  condition: A or (not Prime_Constants_long and maldoc_OLE_file_magic_number) or true
}

rule C {
  condition: false
}
