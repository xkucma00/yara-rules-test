rule C {
  changed = true
  strings:
    $s1= "this string won't match with anything at all"
  condition: $s1
}
