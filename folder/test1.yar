include "test2.yar"
import "pe"

rule C {
  strings:
    $s1= "this string won't match with anything at all"
  condition: 
    $s1 and pe.number_of_sections == 7 and not maldoc_OLE_file_magic_number
}
