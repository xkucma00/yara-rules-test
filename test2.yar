import "pe"

rule fails {
  condition:
    pe.number_of_sections == 5
}
