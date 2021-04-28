# connecting some stuff
from random import randrange
from sys import stdout
from sys import argv
import msvcrt

# opening file
if len(argv) == 1:
	print("no input")
	raise SystemExit

try:
	with open(argv[1]) as f:
		data = f.read()
except:
	print("failed to open %s" % argv[1])
	raise SystemExit

# removing comments
code = []
lidx = []
i = 1

for line in data.split("\n"):
	try:
		line = line[:line.index("=")]
	except:
		pass
	line = line.strip()

	if line:
		code.append(line)
		lidx.append(i)
	i += 1

# runtime stuff
arg_check = {
	"end": 0,
	"set": 1,
	"add": 1,
	"sub": 1,
	"and": 1,
	"orb": 1,
	"xor": 1,
	"mov": 0,
	"pop": 0,
	"rec": 0,
	"res": 0,
	"inc": 0,
	"dec": 0,
	"out": 0,
	"int": 1,
	"str": 2,
	"inp": 0,
	"rng": 0,
	"lab": 2,
	"jmp": 2,
	"equ": 2,
	"neq": 2,
	"gtr": 2,
	"lss": 2,
	"geq": 2,
	"leq": 2,
	"jsr": 2,
	"rts": 0,
	"rol": 0,
	"ror": 0
	#"dbg": 0
}

class Run:
	stream = bytearray(256)
	labels = {}
	stack = []
	index = 0

	reg = 0
	buf = 0

	@classmethod
	def error(cls, text):
		print("line %s: %s" % (lidx[cls.index], text))
		raise SystemExit

	@classmethod
	def push(cls, value):
		for i in range(255):
			cls.stream[i] = cls.stream[i + 1]
		cls.stream[255] = value

	@classmethod
	def pop(cls):
		cls.reg = cls.stream[255]
		for i in range(255):
			cls.stream[i + 1] = cls.stream[i]

	@classmethod
	def ror(cls):
		for i in range(255):
			cls.stream[254 - i], cls.stream[255 - i] = cls.stream[255 - i], cls.stream[254 - i]

	@classmethod
	def rol(cls):
		for i in range(255):
			cls.stream[i], cls.stream[i + 1] = cls.stream[i + 1], cls.stream[i]

	@classmethod
	def input(cls):
		stdout.flush()
		value = msvcrt.getch()[0]
		if value == 0xE0 or value == 0x00:
			return msvcrt.getch()[0] | 0xC0
		return value

	@classmethod
	def parselab(cls):
		index = 0
		for line in code:
			spl = line.split()
			if spl[0] == "lab":
				cls.labels[" ".join(spl[1:])] = index
			index += 1

	@classmethod
	def loop(cls):
		while cls.index < len(code):
			line = code[cls.index].split()
			size = len(line) - 1

			arg = " ".join(line[1:])
			inst = line[0]

			if inst not in arg_check:
				cls.error("unknown instruction %s" % inst)

			it = arg_check[inst]
			if it == 0:
				if size:
					cls.error("instruction %s takes no arguments" % inst)
			elif it == 1:
				if size != 1:
					cls.error("instruction %s takes 1 byte" % inst)
				try:
					arg = int(arg, 0)
					assert arg >= 0 and arg < 256
				except Exception:
					cls.error("%s is not a byte" % arg)
			else:
				if size == 0:
					cls.error("instruction %s takes 1 string" % inst)

			if inst == "end":
				return

			elif inst == "set":
				cls.reg = arg
			elif inst == "add":
				cls.reg = (cls.reg + arg) % 256
			elif inst == "sub":
				cls.reg = (cls.reg - arg) % 256
			elif inst == "and":
				cls.reg &= arg
			elif inst == "orb":
				cls.reg |= arg
			elif inst == "xor":
				cls.reg ^= arg
			elif inst == "mov":
				cls.push(cls.reg)
			elif inst == "pop":
				cls.pop()
			elif inst == "rec":
				cls.buf = cls.reg
			elif inst == "res":
				cls.reg = cls.buf
			elif inst == "inc":
				cls.reg = (cls.reg + 1) % 256
			elif inst == "dec":
				cls.reg = (cls.reg - 1) % 256
			elif inst == "out":
				print(chr(cls.reg), end="")
			elif inst == "int":
				if arg == 2:
					print(bin(cls.reg)[2:].rjust(8, "0"), end="")
				elif arg == 8:
					print(oct(cls.reg)[2:], end="")
				elif arg == 16:
					print(hex(cls.reg)[2:].rjust(2, "0"), end="")
				else:
					print(cls.reg, end="")
			elif inst == "str":
				print(arg.replace("\\s", " ").replace("\\n", "\n").replace("\\t", "\t").replace("\\r", ""), end="")
			elif inst == "inp":
				cls.reg = cls.input()
			elif inst == "rng":
				cls.reg = randrange(256)
			elif inst == "lab":
				pass
			elif inst == "jmp":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				cls.index = cls.labels[arg]
				continue
			elif inst == "equ":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg == cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "neq":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg != cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "gtr":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg > cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "lss":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg < cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "geq":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg >= cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "leq":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				if cls.reg <= cls.buf:
					cls.index = cls.labels[arg]
					continue
			elif inst == "ror":
				cls.ror()
			elif inst == "rol":
				cls.rol()
			elif inst == "jsr":
				if arg not in cls.labels:
					cls.error("label %s is not defined" % arg)
				cls.stack.append(cls.index)
				cls.index = cls.labels[arg]
			elif inst == "rts":
				try:
					cls.index = cls.stack.pop()
				except:
					pass
			"""else:
				print("Reg:", cls.reg)
				print("Buf:", cls.buf)
				for i in range(16):
					for j in range(16):
						print("%02x" % cls.stream[i * 16 + j], end=" ")
					print()"""

			cls.index += 1

try:
	Run.parselab()
	Run.loop()
except KeyboardInterrupt:
	print("Terminated.")
