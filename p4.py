import sys
import re
import datetime

class HashTable():

    def __init__(self):
        self.size = 100
        self.key = [None] * self.size
        self.value = [None] * self.size
        self.i = 0
        self.count = 0

    def insert(self, key, data):
        '''
        Inserts the key-data pair, checks for collisions, inserts if symbol tab
        :param key: character string
        :param data: optional integer to be put in symbol table
        :return: return once it is stored
        '''

        start = self.hashFun(key)
        #print("Storing " + key + " " + data)
        for i in list(range(start, self.size)) + list(range(start)):
            if self.count >= 100:
                print("Error: Unable to insert " + key + " " + data + " because the symbol table is full!")
                break
            if self.key[i] == key:
                print("ERROR: DUPLICATE LABEL " + key + " " + data + " ALREADY AT LOCATION " + str(i))
                break
            if self.key[i] is not None:
                #print("Collision at index " + str(i))
                continue
            self.key[i] = key
            self.value[i] = data
            #print("   Stored at " + str(i))
            symbol_line = [str(i), key, data]
            symbols.addToSymbolTable(symbol_line)
            self.count = self.count + 1
            return

    def search(self, key):
        '''
        :param key: string to be searched for
        :return: return empty list if key does not exist or is not found
        '''

        start = self.hashFun(key)
        for i in list(range(start, self.size)) + list(range(start)):
            if self.key[i] is None:
                return []
            elif self.key[i] == key:
                print("Found " + self.key[i] + " " + self.value[i] + " at location " + str(i))
                return [i]
        return []

    def hashFun(self, key):
        '''
        :param key: takes a string as key, hashes it as an ASCII value
        :return: Remainder of sum of ASCII values
        '''

        sum = 0
        for pos in range(len(key)):
            sum = sum + ord(key[pos])
        return sum % self.size

    def parse(self, content):

        for split in content:
            if len(split) > 2:
                print("Error: input must be a key-value pair separated by whitespace")
                continue
            elif len(split) == 2:  # insert entry in symbol table if length of list is 2
                if split[1].isdigit():
                    hash_table.insert(split[0], split[1])
                else:
                    print("Error: " + split[0] + " " + split[1] + " is an invalid key-value pair")
                    continue
            elif len(split) == 1:  # search for entry in symbol table if length of list is 1
                entry = hash_table.search(split[0])
                if len(entry) == 0: # if entry is returned as empty list, it is not found
                    print("Error: " + split[0] + " not found")

class Symbols():

    def __init__(self, lab_ins_op=[]):
        self.lab_ins_op = lab_ins_op

    def addToSymbolTable(self, symbol_line):

        self.lab_ins_op.append(symbol_line)

    def printSymbolTable(self, lab_ins_op):

        print("\n")
       # print("Loc Label Address")
        for line in lab_ins_op:
            if line is not None:
                line[2] = line[2].zfill(5)  # pads zeroes to addresses
                line = ' '.join(map(str, line))
                line = line.upper()
     #           print(line)

        return lab_ins_op

class File():

    def __init__(self, testfile=[], literals = []):
        self.testfile = testfile
        self.literals = literals

    def handleFile(self):

        if len(sys.argv) != 2:
            print("\nUsage: " + sys.argv[0] + " filename")
            sys.exit(0)
        try:
            with open(sys.argv[1]) as f:
                file = myfile.parseData(f)
                return file
        except IOError:
            print("File " + sys.argv[0] + " does not exist")
            sys.exit(1)

    def parseData(self, f):
        '''
        Gets data from argv[1]
        :return: Linked list of linked lists
        '''

        emptyfile = []
        for line in f:
            line = re.sub(" +", " ", line)  # replace extraneous whitespace with " "
            line = line.rstrip()  # remove trailing whitespace
            line = line.upper()
            emptyfile.append(line)
        file = [line for line in emptyfile if line]
        return file

    def getLTORGindeces(self, testfile):
        indeces = []
        str = ' LTORG'
        for i in range(len(testfile)):
            if testfile[i] == str:
                indeces.append(i)

        return indeces

    def handle_LTORG(self, testfile):

        myfile.testfile = testfile

        for index, line in enumerate(myfile.testfile):
            line = line.split(" ", 3)
            if len(line) > 2:
                if line[2].startswith("=X") or line[2].startswith("=C"):
                    raw_literal = line[2]
                    instruction = 'BYTE'
                    operand = line[2][1:]
                    literal = [raw_literal, instruction, operand]
                    literal = ' '.join(literal)
                    myfile.literals.append(literal)
            if line[1] == 'LTORG':
                if myfile.literals:
                    i = 'hi'
                    while len(i) > 0:
                        i = myfile.literals[-1]
                        myfile.testfile.insert(index+1, str(i))
                        myfile.literals.pop()
                        if len(myfile.literals) == 0:
                            break

        return myfile.testfile


    def printAssembler(self, sicasm):

        for line in sicasm:
            line[0] = line[0].zfill(5) # pads zeroes to addresses

        newlist = [[x[0]] + x[1] if len(x) >= 2 else x for x in sicasm] # removes nested list
        for line in newlist:
            line = ' '.join(line)
            line = line.upper()
           # print(line)

        return newlist

class FirstPass():

    def __init__(self, testfile, split_line=[], addresses=[], final_file=[], next_addresses=[]):
        self.testfile = testfile
        self.split_line = split_line
        self.addresses = addresses
        self.final_file = final_file
        self.next_addresses = next_addresses

    def parseLine(self):

        for line in p1.testfile:
            spaces = re.findall(r"[\s]+", line) # count spaces
            if len(spaces) >= 1: # split linked list of strings into linked list of lists
                p1.split_line = line.split(" ", 3)
                if re.match(r'^\.', line): # ignore comments
                    p1.addresses.append('')
                    p1.final_file.append([line])
                    continue # go to next instruction
                p1.tryParse(p1, lab_ins_op)

        return p1.final_file


    def tryParse(self, p1, lab_ins_op):

        if p1.split_line[1] in ass_dir:
            p1.parseAssemblerDirective(p1, lab_ins_op)
        if p1.split_line[1] in lab_fmts:
            p1.parseInstruction(p1)
        if p1.split_line[1] not in lab_fmts and p1.split_line[1] not in ass_dir:
            print("ERROR: " + p1.split_line[1] + " is an INVALID MNEMONIC")
            p1.parseAssemblerDirective(p1, lab_ins_op)

    def parseAssemblerDirective(self, p1, lab_ins_op):

        for elem in p1.split_line:
            if 'START' in p1.split_line[1]:
                if p1.split_line[2]:
                    operand = p1.split_line[2]
                    elem = int(operand, 16)
                if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                    hash_table.insert(p1.split_line[0], str(hex(elem))[2:])
                    p1.final_file.append([hex(elem)[2:], p1.split_line])
                    p1.addresses.append(elem)
                    p1.next_addresses.append(elem)
                    return

        if 'START' in p1.split_line[1]:
            p1.currentValue = elem
            p1.nextAddress = int(p1.currentValue)
            p1.next_addresses.append(p1.nextAddress)
            if not p1.split_line[2].startswith("-") and len(p1.split_line) >= 2 and p1.split_line[0] != "":
                hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
            p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
            p1.addresses.append(p1.currentValue)
            return

        elif 'LTORG' in p1.split_line:
            p1.addresses.append(p1.next_addresses[-1])
            p1.final_file.append([hex(p1.next_addresses[-1])[2:], p1.split_line])

        elif 'RESW' in p1.split_line[1]:  # parse RESERVED WORD (more parsing will be added in pass 2!)
            if p1.split_line[2].isdigit():
                operand = 3 * int(p1.split_line[2])  # bytes is word * operand
                p1.calculateAddress(p1, operand)
            else:
                print("ERROR: " + p1.split_line[1] + " must be followed by a number (location " + str(hex(p1.next_addresses[-1]))[2:] + ").")
                operand = 0
                p1.calculateAddress(p1, operand)

        elif "WORD" in p1.split_line[1] and not '':  # parse WORD
            operand = 3
            p1.calculateAddress(p1, operand)

        elif "RESB" in p1.split_line[1] and not '':
            operand = 1 * int(p1.split_line[2])  # bytes is 1 byte * operand
            p1.calculateAddress(p1, operand)

        elif 'END' in p1.split_line:
            p1.parseENDAssDir(p1)
            return

        elif (not p1.split_line[0].startswith('=X') or p1.split_line[0].startswith('=C')) and 'BYTE' in p1.split_line[1]:
            if p1.split_line[2][0] == "X" and p1.split_line[2][1] == "'" and p1.split_line[2][-1] == "'":
                if (len(p1.split_line[2]) - 3) % 2 == 0:
                    p1.currentValue = p1.next_addresses[-1]
                    operand = int(len(p1.split_line[2][2:-1])/2)
                    p1.nextAddress = int(operand) + int(p1.currentValue)
                    p1.next_addresses.append(p1.nextAddress)
                    p1.next_addresses.pop(0)
                    if len(p1.split_line) >= 2 and len(p1.split_line[0]) != "":
                        hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
                    p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
                    p1.addresses.append(p1.currentValue)
                else:
                    print("ERROR: " + p1.split_line[2] + " has an odd number of bytes!")
                    p1.currentValue = p1.next_addresses[-1]
                    p1.nextAddress = int(p1.currentValue)
                    p1.next_addresses.append(p1.nextAddress)
                    p1.next_addresses.pop(0)
                    if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                        hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])
                    p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
                    p1.addresses.append(p1.currentValue)

            if p1.split_line[2][0] == "C" and p1.split_line[2][1] == "'" and p1.split_line[2][-1] == "'":
                p1.currentValue = p1.next_addresses[-1]
                operand = int(len(p1.split_line[2][2:-1]))
                p1.nextAddress = int(operand) + int(p1.currentValue)
                p1.next_addresses.append(p1.nextAddress)
                p1.next_addresses.pop(0)
                if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                    hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
                p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
                p1.addresses.append(p1.currentValue)

        elif 'BYTE' in p1.split_line[1] and 'LTORG' not in p1.testfile:
            p1.parseLiteral(p1)

        elif len(p1.split_line) >= 2 and p1.split_line[0] != "":
            hash_table.insert(p1.split_line[0], str(hex(p1.next_addresses[-1]))[2:])
            p1.final_file.append([hex(p1.next_addresses[-1])[2:], p1.split_line])
            p1.addresses.append(p1.next_addresses[-1])

        elif p1.split_line[1] and not "" and p1.split_line[1] != 'START' and p1.split_line[1] != 'BYTE':  # process regular assembler directive, do not add anything to current address list, take off unnecessary and condition
            p1.addresses.append(p1.next_addresses[-1])
            p1.final_file.append([hex(p1.next_addresses[-1])[2:], p1.split_line])
            if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                hash_table.insert(p1.split_line[0], str(hex(p1.next_addresses[-1]))[2:])

    def parseENDAssDir(self, p1):

        currentValue = p1.next_addresses[-1]
        nextAddress = int(currentValue)
        p1.next_addresses.append(nextAddress)
        p1.next_addresses.pop(0)
        if len(p1.split_line) >= 2 and p1.split_line[0] != "":
            hash_table.insert(p1.split_line[0],
                              str(hex(currentValue))[2:])  # take line and add to symbol table if there's a label
        p1.final_file.append([hex(currentValue)[2:], p1.split_line])
        p1.addresses.append(currentValue)

    def parseLiteral(self, p1):

        if p1.split_line[2].startswith("X'"):
            if (len(p1.split_line[2]) - 3) % 2 == 0:
                p1.currentValue = p1.next_addresses[-1]
                operand = int(len(p1.split_line[2][2:-1]) / 2)
                p1.nextAddress = int(operand) + int(p1.currentValue)
                p1.next_addresses.append(p1.nextAddress)
                p1.next_addresses.pop(0)
                if len(p1.split_line) >= 2 and len(p1.split_line[0]) != "":
                    hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
                p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
                p1.addresses.append(p1.currentValue)
            else:
                print("ERROR: " + p1.split_line[2] + " has an odd number of bytes!")
                p1.currentValue = p1.next_addresses[-1]
                p1.nextAddress = int(p1.currentValue)
                p1.next_addresses.append(p1.nextAddress)
                p1.next_addresses.pop(0)
                if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                    hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])
                p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
                p1.addresses.append(p1.currentValue)

        if p1.split_line[2].startswith("C'"):
            p1.currentValue = p1.next_addresses[-1]
            operand = int(len(p1.split_line[2][2:-1]))
            p1.nextAddress = int(operand) + int(p1.currentValue)
            p1.next_addresses.append(p1.nextAddress)
            p1.next_addresses.pop(0)
            if len(p1.split_line) >= 2 and p1.split_line[0] != "":
                hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
            p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
            p1.addresses.append(p1.currentValue)
            return

    def calculateAddress(self, p1, operand):

        p1.currentValue = p1.next_addresses[-1]
        p1.nextAddress = int(operand) + int(p1.currentValue)
        p1.next_addresses.append(p1.nextAddress)
        p1.next_addresses.pop(0)
        if len(p1.split_line) >= 2 and p1.split_line[0] != "":
            hash_table.insert(p1.split_line[0], str(hex(p1.currentValue))[2:])  # take line and add to symbol table if there's a label
        p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
        p1.addresses.append(p1.currentValue)

    def checkLabelInSymbolTable(self, p1):

        if len(p1.split_line) > 0:
            if p1.split_line[1] == 'RSUB':
                currentVaue = p1.next_addresses[-1]
            if p1.split_line[2].startswith("#") and p1.split_line[2].isalpha() and p1.split_line[2][1:] not in lab_ins_op:
                print("ERROR: label " + str(p1.split_line[2][1:]) + " missing from symbol table at location " + str(hex(p1.next_addresses[-1]))[2:])
        else:
            return

    def assemble(self, p1):

        p1.currentValue = p1.next_addresses[-1]
        p1.nextAddress = int(p1.currentValue) + int(lab_fmts.get(p1.split_line[1]))
        p1.next_addresses.append(p1.nextAddress)
        p1.next_addresses.pop(0)
        p1.final_file.append([hex(p1.currentValue)[2:], p1.split_line])
        p1.addresses.append(p1.currentValue)

    def assembleLiteral(self, p1, ltorgs):

        instruction = 'BYTE'
        operand = p1.split_line[2][1:]
        literal = [p1.split_line[2], instruction, operand]
        literal = ' '.join(literal)
        #p1.testfile = p1.testfile[p1.testfile.index(p1.split_line) + 1:]
        #p1.testfile.append(literal)
        if ' LTORG' not in testfile:                # fix this bit
            p1.testfile2.append(literal)
        else:
            pass
        p1.assemble(p1)

    def parseInstruction(self, p1):

        if len(p1.split_line) > 2:
            p1.checkLabelInSymbolTable(p1)

        if len(p1.split_line) > 2:
            if p1.split_line[2].startswith("=X") or p1.split_line[2].startswith("=C"):
                p1.assembleLiteral(p1, ltorgs)
                return

        if p1.split_line[1]:

            if len(p1.next_addresses) == 0:
                p1.nextAddress = int(lab_fmts.get(p1.split_line[1]))
                p1.next_addresses.append(p1.nextAddress)
            else:
                nextAddress = int(lab_fmts.get(p1.split_line[1])) + int(p1.next_addresses[-1])

            if p1.split_line[0] == "":  # if instruction has no label
                if p1.split_line[1] == 'RSUB':  # if RSUB instruction, just stick with current value
                    p1.assemble(p1)
                    return

            if len(p1.split_line) >= 2 and p1.split_line[0] != "":  # insert to symbol table if theres a label
                hash_table.insert(p1.split_line[0], hex(p1.next_addresses[-1])[2:])
                p1.assemble(p1)

            if len(p1.split_line) >= 2 and p1.split_line[0] == "":  # do not insert into symbol table
                p1.assemble(p1)

class SecondPass():

    def __init__(self, sicasm = [], objectcode = [], opcode=[], flags=[], displacement=[], format=[]):
        self.sicasm = sicasm
        self.objectcode = objectcode
        self.opcode = opcode
        self.flags = flags
        self.displacement = displacement
        self.format = format

    def tryParse(self, lab_ins_op):

        for p2.line in p2.sicasm: # list of length 1 is a comment, must skip.
            if len(p2.line) != 1 and p2.line[2] in lab_ops:
                p2.parseInstruction(p2, lab_ins_op)
            if len(p2.line) != 1 and p2.line[2] in ass_dir:
                p2.parseAssembly(p2, lab_ins_op)
           # print(p2.line)

    def parseAssembly(self, p2, lab_ins_op):

        if p2.line[1] == 'START':
            return
        elif p2.line[2] == 'BYTE':
            for literal in lab_ins_op:
                if literal[1] == p2.line[1] and (literal[1].startswith("=X") or literal[1].startswith("=C")):
                    literal_operand = literal[1][2:] #gets what's inside of "x'1d'"
                    literal_operand = literal_operand.strip('\'') # remove ''
                    p2.line.insert(1, str(literal_operand))
                    return

        elif p2.line[2] == 'WORD':
            objectcode = int(str(p2.line[3]))
            if objectcode < 0:
                objectcode = str(objectcode & 0xF)
                while len(objectcode) < 6:
                    objectcode = "F" + objectcode
                p2.line.insert(1, str(objectcode))
            else:
                p2.line.insert(1, str(objectcode).zfill(6))
            return

    def parseInstruction(self, p2, lab_ins_op):

        p2.opcode = p2.getOpcode(p2, lab_ops)
        p2.format = p2.getFormat(p2, lab_fmts)

        if p2.format == '3':
            p2.parseFormat3Instruction(p2, lab_ins_op)
        elif p2.format == '4':
            p2.parseFormat4Instruction(p2, lab_ins_op)
        elif p2.format == '2':
            p2.parseFormat2Instruction(p2, lab_ins_op)

    def parseFormat2Instruction(self, p2, lab_ins_op):

        opcode = p2.getOpcode(p2, lab_ops)

        r1 = p2.line[3][:-2]
        r2 = p2.line[3][-1]
        r1 = p2.getRegister(r1, registers)
        r2 = p2.getRegister(r2, registers)

        objectcode = opcode + r1 + r2
        p2.line.insert(1, str(objectcode))

    def parseFormat3Instruction(self, p2, lab_ins_op):

        if 'RSUB' in p2.line:
            opcode = str(hex(int(p2.opcode, 16) + 3)[2:]).zfill(2)
            displacement = '0000'
            objectcode = opcode + displacement
            p2.line.insert(1, str(objectcode))
            return

        operandIsImmediate = p2.checkOperandImmediate(p2)
        operandIsIndirect = p2.checkOperandIndirect(p2)

        pcDisplacement = str(p2.calculateDisplacement(p2, lab_ins_op))[2:].zfill(3)

        if not p2.isPCRelative and not operandIsImmediate and not operandIsIndirect: #base relative, n,i are on
            baseDisplacement = str(p2.calculateBaseDisplacement(p2, lab_ins_op)).zfill(3)
            opcode = str(int(p2.opcode, 16) + 3).zfill(2)
            b = str(4)
            objectcode = opcode + b + baseDisplacement
            p2.line.insert(1, str(objectcode))
            return

        if p2.isPCRelative and operandIsImmediate:
            if p2.line[3][1:].isdigit(): # immediate and operand is a digit, not a label
                opcode = str(int(p2.opcode, 16) + 1).zfill(2) # opcode is opcode + "i" bit
                operand = int(p2.line[3][1:]) # take immediate address in decimal
                hex_operand = str(hex(operand)[2:]).zfill(4) # convert new immediate addresss to hex
                objectcode = opcode + hex_operand
                p2.line.insert(1, str(objectcode))
            elif p2.line[3][1:].isalpha():
                opcode = str(hex(int(p2.opcode, 16) + 1)[2:]).zfill(2) # opcode = opcode + "i" bit
                p = str(2) # p bit
                displacement = str(hex(p2.displacement)[2:]).zfill(3)
                objectcode = opcode + p + displacement
                p2.line.insert(1, str(objectcode))

        elif p2.isPCRelative and ',' in p2.line[3]:
            opcode = str(hex(int(p2.opcode,16) + 3)[2:]).zfill(2)
            x = 'A'
            displacement = str(hex(p2.displacement))[2:].zfill(3)
            objectcode = opcode + x + displacement
            p2.line.insert(1, str(objectcode))

        elif p2.isPCRelative and operandIsIndirect:
            opcode = str(hex(int(p2.opcode, 16) + 2))[2:].zfill(2) # opcode = opcode + "n" bit
            p = str(2)
            displacement = str(hex(p2.displacement)[2:]).zfill(3)
            objectcode = opcode + p + displacement
            p2.line.insert(1, str(objectcode))

        elif p2.isPCRelative and not operandIsIndirect and not operandIsImmediate: # simply PC relative
            opcode = str(hex(int(p2.opcode, 16) + 3)[2:]).zfill(2)
            p = str(2)
            displacement = str(hex(p2.displacement))[2:].zfill(3)
            objectcode = opcode + p + displacement
            p2.line.insert(1, str(objectcode))

        elif not p2.isPCRelative and operandIsImmediate: #Immediate but not PC Relative (Address is in the instruction!)
            opcode = str(hex(int(p2.opcode, 16) + 3)[2:]).zfill(2)
            instruction = p2.line[3][1:]
            instruction = str(hex(int(instruction, 16))[2:]).zfill(4)
            objectcode = opcode + instruction
            p2.line.insert(1, str(objectcode))

    #    pcDisplacement = pcDisplacement[2:]
    #    if int(pcDisplacement, 16) > int(str(2047), 16) and operandIsImmediate:
    #        baseDisplacement = str(p2.calculateBaseDisplacement(p2, lab_ins_op))
    #        if p2.line[3][1].isalpha() and any(char.isdigit() for char in p2.line[3][1::]): # checks if there is a label that has digits and alphanumeric (BASE RELATIVE)
    #            opcode = str(int(p2.opcode) + 1).zfill(2)
    #            p = str(4) # p bit
    #            objectcode = opcode + p + baseDisplacement
    #            p2.line.insert(1, str(objectcode))

    def parseFormat4Instruction(self, p2, lab_ins_op):

        operandIsImmediate = p2.checkOperandImmediate(p2)
        operandIsIndirect = p2.checkOperandIndirect(p2)
     #   print(p2.line)
        if operandIsImmediate:
            opcode = str(int(p2.opcode) + 1)
            operand = p2.line[3][1:]
            address = p2.getAddressFromSymbolTable(p2, operand, lab_ins_op)
            objectcode = opcode + str(1) + address
            p2.line.insert(1, str(objectcode))
        elif operandIsIndirect:
            opcode = str(int(p2.opcode) + 2)
            operand = p2.line[3][1:]
            address = p2.getAddressFromSymbolTable(p2, operand, lab_ins_op)
            objectcode = opcode + str(1) + address
            p2.line.insert(1, str(objectcode))
        elif ',' in p2.line[3]:
            opcode = str(hex(int(p2.opcode, 16) + 3))[2:].zfill(2)
            operand = p2.line[3]
            operand = operand.split(',')[0]
            xe = '9'
            address = p2.getAddressFromSymbolTable(p2, operand, lab_ins_op)
            objectcode = opcode + xe + address
            p2.line.insert(1, str(objectcode))
        else: #operandISPCRelative
            opcode = str(hex(int(p2.opcode, 16) + 3))[2:].zfill(2)
            operand = p2.line[3]
            address = p2.getAddressFromSymbolTable(p2, operand, lab_ins_op)
            objectcode = opcode + str(1) + address
            p2.line.insert(1, str(objectcode))

    def getAddressFromSymbolTable(self, p2, operand, lab_ins_op):

        for line in lab_ins_op:
            if operand == line[1]:
                return line[2]

    def getBaseAddress(self, label, lab_ins_op):

        for line in lab_ins_op:
            if line[1] == label:
                baseAddress = line[2]
                return baseAddress

    def getBaseLabel(self):

        for line in newlist:
            if line[2] == 'BASE':
                baseOperand = line[3]
                return baseOperand

    def getOperandAddress(self, operandLabel, lab_ins_op):

        for symbols in lab_ins_op:
            if symbols[1] == operandLabel:
                operandAddress = symbols[2]
                return operandAddress

    def calculateDisplacement(self, p2, lab_ins_op):

        operand = p2.line[3] # operand
        if operand.startswith("#"): #or operand.startswith("@"):
            if operand[1:].isdigit():
                operand = operand[1:]
                p2.isPCRelative = False
                displacement = 0
                return displacement
            elif operand[1:].isalpha() or operand[1:].isalpha() and any(char.isdigit() for char in operand[1::]): # checks if there is a label that has digits and alphanumeric
                operand = operand[1:]
                p2.isPCRelative = True
        elif operand.startswith("@"):
            operand = operand[1:]
            p2.isPCRelative = True
            #return operand
        elif ',' in operand: # indexed instruction
            operand = operand.split(',')
            operand = operand[0]
            p2.isPCRelative = True

        operandAddress = int(p2.line[0], 16) # subtracted address
        operandAddress = str(hex(operandAddress))[2:]

        for line in lab_ins_op:  # calculates positive displacement
            if operand == line[1]:  # if operand matches label in symbol table
                labelAddress = line[2]  # label from symbol table that we subtract from
                displacement = int(labelAddress, 16) - (int(operandAddress, 16) + 3)
                if displacement >= -2048 and displacement <= 2047:
                    p2.displacement = int(str(displacement).zfill(3))
                    p2.isPCRelative = True
                    if p2.displacement < 0: # do 2's complement if the displacement is negative
                        p2.displacement = p2.displacement & 0xFFF
                    return
                displacement = abs(displacement)
                if displacement > 4095:
                    displacement = p2.calculateBaseDisplacement(p2, lab_ins_op)
                    p2.displacement = displacement
                    p2.isPCRelative = False
                    return

    def fixOperandLabel(self, operandLabel):

        if operandLabel.startswith("#") or operandLabel.startswith("@"):
            operandLabel = operandLabel[1:]
            return operandLabel
        else:
            return operandLabel

    def calculateBaseDisplacement(self, p2, lab_ins_op):

        operandLabel = p2.fixOperandLabel(p2.line[3]) # operand of instruction that we subtract fro
        baseLabel = p2.getBaseLabel() # checks newlist to see what the operand of BASE is

        baseAddress = int(p2.getBaseAddress(baseLabel, lab_ins_op), 16) # gets address of base label from symbol table
        operandAddress = int(p2.getOperandAddress(operandLabel, lab_ins_op), 16) # THIS IS WRONG

        baseDisplacement = operandAddress - baseAddress
        baseDisplacement = hex(baseDisplacement)[2:]

        return baseDisplacement

    def getFormat(self, p2, lab_fmts):
        instruction = str(p2.line[2])
        format = lab_fmts.get(instruction)
        return format

    def checkOperandImmediate(self, p2):
        if 'RSUB' in p2.line:
            return
        else:
            operand = str(p2.line[3])
            return operand.startswith("#")

    def checkOperandIndirect(self, p2):
        if 'RSUB' in p2.line:
            return
        else:
            operand = str(p2.line[3])
            return operand.startswith("@")

    def getOpcode(self, p2, lab_ops):

        instruction = str(p2.line[2])
        opcode = lab_ops.get(instruction)
        return opcode

    def getRegister(self, registerno, registers):

        register = registers.get(registerno)
        return register

class makeLST():

    def __init__(self, sicasm=[], lst=[]):
        self.sicasm = sicasm
        self.lst = lst

    def getDateTime(self):
        time = datetime.datetime.now()
        return time

    def makeHeader(self, time):

        header = ['*********************************************',
                  'University of North Florida: SIC/XE assembler',
                  str(time),
                  'Written By: Afnan Sultan: N01154597',
                  '*********************************************',
                  'ASSEMBLER REPORT',
                  '----------------',
                  'Loc     Object Code Source Code',
                  '---     ----------- -----------']
        return header

    def addLineNumber(self, sicasm):

        for i in range(len(sicasm)):
            sicasm[i] = [i+1] + sicasm[i]
        return sicasm

    def printPass2(self, sicasm):

        newsicasm = lst.addLineNumber(sicasm)

        for i in range(len(sicasm)):
            sicasm[i] = list(map(str, sicasm[i]))

        return sicasm

class makeOBJ():

    def __init__(self, newlist=[], obj_file=[], RESWs = 0):
        self.newlist = newlist
        self.obj_file = obj_file
        self.RESWs = RESWs

    def grabStartAddress(self, newlist):

        for line in newlist:
            if 'START' in line:
                start_address = line.index('START') + 1
                start_address = line.pop(start_address)
                return start_address
        else:
            start_address = '000000'
            return start_address

    def countRESWs(self, newlist):

        RESW_count = 0

        for line in newlist:
            if "RESW" in line:
                RESW_count = RESW_count + 1
        return RESW_count

    def getAddressAfterEND(self, newlist):

        for line in newlist:
            if 'END' in line and len(line) > 3:
                end_label_index = line.index('END') + 1
                end_label = line.pop(end_label_index)
                end_address = str(p2.getOperandAddress(end_label, lab_ins_op)).zfill(6)
                return end_address
        else:
            return None

    def assembleObjectCode(self, newlist):

        start_address = str(object_code.grabStartAddress(newlist)).zfill(6)
        object_code.obj_file.append(start_address) # get start address, append it as first line of obj file

        end_address = object_code.getAddressAfterEND(newlist)

        if end_address == None: # pad 0s if there is a label after end operand
            end_address = str(object_code.getAddressAfterEND(newlist)).zfill(6)
            #print(end_address)

        RESW_Count = object_code.countRESWs(newlist) # count the RESWs

        if RESW_Count > 0:
            object_code.obj_file.append('000000') # if RESWs in program, loader is 000000
        elif RESW_Count == 0:
            object_code.obj_file.append(start_address) # if no RESWs, just use start address as loader address
        for i, line in enumerate(newlist):
            if len(line) >= 5:
                object_code.obj_file.append(line[1]) # append object code of line
                continue

            if line[2] == 'RESW':
                object_code.obj_file.append("!")
                RESW_Count = RESW_Count -1
                object_code.obj_file.append(str(newlist[i+1][0]).zfill(6)) #append address of next line

                if RESW_Count == 0 and end_address != None:
                    object_code.obj_file.append(end_address) # no more RESWs and END has an operand
                elif RESW_Count == 0 and end_address == None: # no more RESWs, no operand after END
                    object_code.obj_file.append(start_address)
                elif RESW_Count > 0:
                    object_code.obj_file.append('000000') # if RESWs still in program, use 000000 as loader address
                continue

        object_code.obj_file.append("!")

        my_obj_file = object_code.obj_file
        return my_obj_file


if __name__ == '__main__':

    ass_dir = {'START': '1', 'END': '3', 'EQU': '4', 'ORG': '5',
               'BASE': '6', 'LTORG': '7', 'RESW': '8', 'RESB': '9',
               'BYTE': '10', 'NOBASE': '11', 'WORD': '12'}
    lab_fmts = {'+LDB': '4', 'MULR': '2', '+SSK': '4',
               'WD': '3', '*STX': '3', '*OR': '3', 'AND': '3',
               '*LDA': '3', '+JGT': '4', '+STL': '4', '*WD': '3',
               '+STI': '4', 'LPS': '3', '+LDT': '4', '*LDCH': '4',
               '*LDL': '3', 'TIXR': '2', 'SUBF': '3', '*JSUB': '3',
               'LDX': '3', '+MULF': '4', '+J': '4', 'SVC': '2',
               'STT': '3', '+COMP': '4', 'TIX': '3', 'FLOAT': '1',
               'LDT': '3', 'STA': '3', '*TD': '3', 'SHIFTR': '2',
               'STB': '3', 'SIO': '1', 'LDA': '3', 'HIO': '1',
               '+STS': '4', 'DIVF': '3', "*TIX": '3', '+JSUB': '4',
               'LDCH': '3', '+COMPF': '4', 'JEQ': '3', '*DIV': '3',
               '+STT': '4', '+SUBF': '4', '*AND': '3', '+OR': '4',
               'SSK': '3', '+JLT': '4', '*RD': '3', 'LDS': '3',
               '*MUL': '3', '+LDS': '4', '+DIV': '4', 'J': '3',
               '+MUL': '4', '*COMP': '3', '+STX': '4', '*J': '3',
               '+LDA': '4', '+SUB': '4', '+STB': '4', '*JLT': '3',
               'SUB': '3', '+ADDF': '4', 'RD': '3', '*JEQ': '3',
               'LDB': '3', 'RS[UB': '3', 'MULF': '3', 'JSUB': '3',
               'SUBR': '2', 'DIVR': '2', 'LDL': '3', '+JEQ': '4',
               '+STCH': '4', '*STL': '3', '+STA': '4', 'STSW': '3',
               'COMPF': '3', '+DIVF': '4', '+STF': '4', 'TIO': '1',
               '*ADD': '3', '*STSW': '4', '+STSW': '4', '+LPS': '4',
               'JLT': '3', '*JGT': '3', 'MUL': '3', '+LDL': '4',
               'OR': '3', 'COMP': '3', 'TD': '3', 'STS': '3',
               '*STCH': '3', 'LDF': '3', 'ADD': '3', 'FIX': '1',
               '*RSUB': '3', 'NORM': '1', 'STF': '3', '*LDX': '3',
               'CLEAR': '2', '+RSUB': '4', 'ADDF': '3', '+WD': '4',
               '+LDCH': '4', '+LDF': '4', '+LDX': '4', 'STCH': '3',
               '+ADD': '4', '+AND': '4', '*SUB': '3', 'STX': '3',
               'RMO': '2', 'COMPR': '2', 'SHIFTL': '2', 'STL': '3',
               '+TD': '4', 'ADDR': '2', 'STI': '3', '+TIX': '4',
               '*STA': '3', 'JGT': '3', 'DIV': '3', '+RD': '4', 'RSUB': '3'}
    lab_ops = {'+LDB': '68', 'MULR': '98', '+SSK': 'EC', 'WD': 'DC',
              '*STX': '10', '*OR': '44', 'AND': '40', '*LDA': '00',
              '+JGT': '34', '+STL': '14', '*WD': 'DC', '+STI': 'D4',
              'LPS': 'D0', '+LDT': '74', '*LDCH': '50', '*LDL': '08',
              'TIXR': 'B8', 'SUBF': '5C', '*JSUB': '48', 'LDX':  '04',
              '+MULF': '60', '+J': '3C', 'SVC': 'B0', 'STT': '84',
              '+COMP': '28', 'TIX': '2C', 'FLOAT': 'C0', 'LDT': '74',
              'STA': '0C', '*TD': 'E0', 'SHIFTR': 'A8', 'STB': '78',
              'SIO': 'F0', 'LDA': '00', 'HIO': 'F4', '+STS': '7C',
              'DIVF': '64', '*TIX': '2C', '+JSUB': '48', 'LDCH': '50',
              '+COMPF':  '88', 'JEQ': '30', '*DIV': '24', '+STT': '84',
              '+SUBF': '5C', '*AND': '40', '+OR': '44', 'SSK': 'EC',
              '+JLT': '38', '*RD': 'D8', 'LDS': '6C', '*MUL': '20',
              '+LDS': '6C', '+DIV': '24', 'J': '3C', '+MUL': '20',
              '*COMP': '28', '+STX': '10', '*J': '3C', '+LDA': '00',
              '+SUB': '1C', '+STB': '78', '*JLT': '38', 'SUB': '1C',
              '+ADDF': '58', 'RD': 'D8', '*JEQ': '30', 'LDB': '68',
              'RSUB': '4C', 'MULF': '60', 'JSUB': '48', 'SUBR': '94',
              'DIVR': '9C', 'LDL': '08', '+JEQ': '30', '+STCH': '54',
              '*STL': '14', '+STA': '0C', 'STSW': 'E8', 'COMPF': '88',
              '+DIVF': '64', '+STF': '80', 'TIO': 'F8', '*ADD': '18',
              '*STSW': 'E8', '+STSW': 'E8', '+LPS': 'D0', 'JLT': '38',
              '*JGT': '34', 'MUL': '20', '+LDL': '08', 'OR': '44',
              'COMP': '28', 'TD': 'E0', 'STS': '7C', '*STCH': '54',
              'LDF': '70', 'ADD': '18', 'FIX': 'C4', '*RSUB': '4C',
              'NORM': 'C8', 'STF': '80', '*LDX': '04', 'CLEAR': 'B4',
              '+RSUB': '4C', 'ADDF': '58', '+WD': 'DC', '+LDCH': '50',
              '+LDF': '70', '+LDX': '04', 'STCH': '54', '+ADD': '18',
              '+AND': '40', '*SUB': '1C', 'STX': '10', 'RMO': 'AC',
              'COMPR': 'A0', 'SHIFTL': 'A4', 'STL': '14', '+TD': 'E0',
              'ADDR': '90', 'STI': 'D4', '+TIX': '2C', '*STA': '0C',
              'JGT': '34', 'DIV': '24', '+RD': 'D8'}
    registers = {'A': '0', 'X': '1', 'L': '2', 'PC': '8',
                 'SW': '9', 'B': '3', 'S': '4', 'T': '5',
                 'F': '6'}

    symbols = Symbols() # symbols object is actually lab_ins_op list encapsulated in a class
    lab_ins_op = symbols.lab_ins_op
    hash_table = HashTable()  # Data structure used to populate symbol table

    myfile = File()  # create myfile object to operate on
    testfile = myfile.handleFile() # save file as linked list of strings
    testfile2 = myfile.handle_LTORG(testfile)
    ltorgs = myfile.getLTORGindeces(testfile)

    p1 = FirstPass(testfile2) #p1 object that implements pass one on testfile
    sicasm = p1.parseLine() # parse p1, then save pass 1 output

    newlist = myfile.printAssembler(sicasm) # prints sicasm
    lab_ins_op = symbols.printSymbolTable(symbols.lab_ins_op) # prints symbol table

    #print(newlist)
    #print(lab_ins_op)
    p2 = SecondPass(newlist)
    p2.tryParse(lab_ins_op)

  #  print(newlist)

    object_code = makeOBJ(newlist)
    my_obj_file = object_code.assembleObjectCode(newlist)
    #print(my_obj_file)


    obj_filename = str(sys.argv[1]) + '.obj'

    with open(str(obj_filename), 'w') as fi:
        for line in my_obj_file:
            fi.write("%s\n" % line)


    lst = makeLST(newlist)
    time = lst.getDateTime()
    header = lst.makeHeader(time)

    newsicasm = lst.printPass2(newlist)
    newsicasm = [' '.join([str(c) for c in mylist]) for mylist in newsicasm]

    #print(header)
    #print(newsicasm)

    my_lst_file = header + newsicasm


    lst_filename = str(sys.argv[1]) + ".lst"

    #print(my_lst_file)

    with open(str(lst_filename), 'w') as fil:
        for line in my_lst_file:
            fil.write("%s\n" % line)

    print(lst_filename + " and " + obj_filename +  " generated!")

    #for line in my_lst_file:
    #    print(line)

