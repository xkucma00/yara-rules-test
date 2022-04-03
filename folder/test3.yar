include "../test1.yar"
include "test2.yar"

rule A {
  strings: $s = "Welcome!"
  condition: Prime_Constants_long or $s or false
}

rule C {
  condition: false or true
}
