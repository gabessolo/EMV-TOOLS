# EMV-tag-parser
This is an EMV parser that when you give it a string with EMV data it will show its meaning like the following example:

	6F(File Control Information(FCI) Template)
		1A
		84(Dedicated File(DF) Name)
			0E -len
			315041592E5359532E4444463031 - value(1PAY.SYS.DDF01 en hexa)
		A5(File Control information(FCI) Propietary template)
		08-len
			88(Short File Identifier(SFI))
				01- len
				02 -value
			5F2D(language preference)
				02-len
				656E-value

