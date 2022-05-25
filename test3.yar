include "test2.yar"

private rule relies_on_fail {
  strings:
    $s1 = "not likely to match string"
  condition:
    $s1 and fails
}
