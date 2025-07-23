
# Hey stranger.
# All of the comments in this file are in Brazilian Portuguese.

import threading, time, os, traceback, colorama
from typing import Callable, Dict, Tuple

_F = colorama.Fore
_S = colorama.Style

os.system("cls")
CODENAME = "French Fries"
VERSION = 2507000 #AAMMBBB - Ano / Mês / Build
EXTRA = "BETA"
print(f"{_F.YELLOW}{_S.BRIGHT}PotatOS {_S.NORMAL}\"{CODENAME}\" {_S.BRIGHT}[build {VERSION}] {_F.MAGENTA}{EXTRA}")
print(f"{_S.RESET_ALL}Using {_F.YELLOW}{_S.BRIGHT}Python-based {_F.MAGENTA}Kernel {_F.YELLOW}{_S.NORMAL}\"Potnel\"{_S.RESET_ALL}")
ROOTOS = os.name #posix = linux/macOS | win32 = windows
ROOT = str(os.getcwd()).replace("\\","/") + "/" # A root DEVE ser referida como //

class Kernel: # O Gerenciador do sistema. 
    tasks: Dict[str, Tuple[bool, Callable]] = {}  # {task_name: (is_Kernel_mode, task_func)}
    _lock = threading.Lock()  # Evita race conditions
    
    class MemoryManager: # Gerenciamento de Memória RAM virtual.
        def createDisk(size_kb=1):
            print(f"Creating {size_kb*1024}b RAM disk...")
            Kernel.MemoryManager.ram = bytearray(size_kb*1024)  # 1KB de RAM
            print(f"Creating {size_kb*1024} slots for RAM owners...")
            Kernel.MemoryManager.ram_owners = ["FREE"] * (size_kb * 1024) # Define toda a RAM como livre
            Kernel.MemoryManager.next_addr = 0 # O último endereço livre.
    
        def alloc(size, task): # Reserva um espaço para um programa.
            """ Reserva um espaço na RAM para algum programa.
            task é o programa dono da reserva."""
            
            free = 0
            free_after_addr = 0
            for i,owner in enumerate(Kernel.MemoryManager.ram_owners):
                if owner == "FREE":
                    free += 1
                    if i>=Kernel.MemoryManager.next_addr:
                        free_after_addr +=1
            chkFree = ["FREE"] * size
            listask = [task] * size
            addr = Kernel.MemoryManager.next_addr
            if chkFree != Kernel.MemoryManager.ram_owners[addr:addr+size]:
                if addr+len(chkFree)>len(Kernel.MemoryManager.ram):
                    Kernel.MemoryManager.ram_owners[addr:addr+free_after_addr] = [task] * free_after_addr
                    Kernel.MemoryManager.ram_owners[0:free-free_after_addr] = [task] * (free-free_after_addr)
                else:
                    raise MemoryError(f"Cannot allocate {size} bytes for {task}. Only {free} bytes free.\nADDR={addr}\nTASK={task}")
                
            else:
                Kernel.MemoryManager.ram_owners[addr:addr+size] = listask
            Kernel.MemoryManager.next_addr = (addr+size)%len(Kernel.MemoryManager.ram)
            return addr
        
        def write(addr, data, task): # Escreve em 'addr' como 'task'
            listask = [task] * len(data)
            if listask == Kernel.MemoryManager.ram_owners[addr:addr+len(data)]:
                Kernel.MemoryManager.ram[addr:addr+len(data)] = data
        
        def free(addr, size, task): # Limpa os endereços addr à addr+size de posse de 'task'
            if task == Kernel.MemoryManager.ram_owners[addr:addr+size]:
                Kernel.MemoryManager.ram[addr:addr+size] = [0] * size
                Kernel.MemoryManager.ram_owners[addr:addr+size] = ["FREE"] * size
        
        def kick(task): # Limpa todas as reservas de 'task'
            if task in Kernel.MemoryManager.ram_owners and task != "FREE":
                for i,owner in enumerate(Kernel.MemoryManager.ram_owners):
                    if task == owner:
                        Kernel.MemoryManager.ram[i] = 0
                        Kernel.MemoryManager.ram_owners[i] = "FREE"
        
        def read(addr, size): # Lê algo da memória
            try:
                return Kernel.MemoryManager.ram[addr:addr+size].decode()
            except UnicodeDecodeError:
                return list(Kernel.MemoryManager.ram[addr:addr+size])
            except IndexError:
                print("IOError: Invalid RAM address")
                return 
        
        def nuke(): # Limpa as reservas de todas tarefas mortas.
            active_tasks = [name for name, (_, _) in Kernel.tasks.items()]
            for i, owner in enumerate(Kernel.MemoryManager.ram_owners):
                if owner != "FREE" and owner not in active_tasks:
                    Kernel.MemoryManager.ram[i] = 0
                    Kernel.MemoryManager.ram_owners[i] = "FREE"
        
        def dump(): # Qual é. Dá pra saber o que isso faz!
            print(f"Memory Dump:\n{len(Kernel.MemoryManager.ram)} bytes in {__name__}")
            print(list(Kernel.MemoryManager.ram))
            print(Kernel.MemoryManager.ram.decode())
            print(f"Memory Ownership Dump:")
            print(Kernel.MemoryManager.ram_owners)
        
        def usage(): # Mostra o uso atual da memória
            free = 0
            size = 0
            for owner in Kernel.MemoryManager.ram_owners:
                size += 1
                if owner == "FREE":
                    free += 1
            
            freeButShort = free
            sizeButShort = size
            sizeShort = 0
            sizeShort2 = 0
            sizeList = ['B','KB','MB','GB','TB']
            while freeButShort>1023: # >= 1024
                freeButShort = freeButShort/1024
                sizeShort += 1
            while sizeButShort>1023: # >= 1024
                sizeButShort = sizeButShort/1024
                sizeShort2 += 1
            return free, f"{freeButShort}{sizeShort} free out of {sizeButShort}{sizeShort2}", f"{free} bytes free out of {size}", (free/size)*100, 100-((free/size)*100)
    
    class PotatoFileSystem: # Gerenciamento de Discos virtuais.
        def Pythonfy(path: str): # Transforma Caminhos do Windows, do PotatOS e do Unix em Caminhos tipo Python. (A unica diferença é que a root é // em vez de /)
            isValid = True
            if path == ".":
                path = os.getcwd()
            path = str(path).replace("\\","/")
            path = path.replace("//",ROOT)
            folders = path.split("/")
            for i,folder in enumerate(folders):
                if folder == "": 
                    folders.pop(i) # Remove splits em branco por causa da root ser // (ex: "//media/emulated/".split('/') = ['','','media','emulated',''])
            owpath = str(os.getcwd()).replace("\\","/") + "/"
            for folder in folders:
                if os.path.isfile(folder):
                    break
                wpath = str(os.getcwd()).replace("\\","/")
                if wpath[len(wpath)-1] != "/":
                    wpath = wpath+"/"
                if ROOT not in path:
                    currentWorkdir = os.listdir()
                    if folder in currentWorkdir:
                        path = wpath + path
                        
                    elif path == "..":
                        if wpath != ROOT:
                            path = wpath + "../"
                        else:
                            path = ROOT
                        
                    else:
                        isValid = False
            try:
                if path[len(path)-1] != "/":
                    path = path + "/"
            except IndexError:
                isValid = False
                path = ROOT
            return isValid,path
        
        def Spudify(path: str): # Transforma Caminhos tipo Python no formato do PotatOS
            if len(path)==0 or path == ".":
                path = os.getcwd()
            path = str(path).replace("\\","/")
            path = path.replace(ROOT,"//")
            if path[len(path)-1] != "/":
                path = path + "/"
            if "//" not in path:
                path = "//"
            return path
        
        def changeDirectory(path: str): # Esse tá na cara o que faz.
            valid, upath = Kernel.PotatoFileSystem.Pythonfy(path)
            if valid:
                os.chdir(upath)
            else:
                print("Invalid path")
        
        def createFile(filename: str, content: list): # Cria um arquivo dentro do sistema de arquivos do PotatOS.
            folders = filename.split("/")
            for folder in enumerate(folders):
                    folders.remove('')
            path2File = ""
            for folder in folders[:len(folders)-1]:
                path2File = os.path.join(path2File, folder)
            path2File = Kernel.PotatoFileSystem.Spudify(path2File)
            valid, upath = Kernel.PotatoFileSystem.Pythonfy(path2File)
            
            if valid:
                with open( upath+filename, 'w' ) as f:
                    for line in content:
                        f.write(str(line) + "\n")
            else:
                print("Invalid path.")
                
        def getFile(filename: str): # Lê um arquivo dentro do sistema de arquivos do PotatOS.
            filename = str(filename)
            folders = filename.split("/")
            for folder in enumerate(folders):
                try:
                    folders.remove('')
                except ValueError:
                    break
            path2File = ""
            for folder in folders[:len(folders)-1]:
                path2File = os.path.join(path2File, folder)
            path2File = Kernel.PotatoFileSystem.Spudify(path2File)
            valid, upath = Kernel.PotatoFileSystem.Pythonfy(path2File)
            
            if valid:
                with open( upath+filename, 'r' ) as f:
                        return f
            print("Invalid path.")
    
    calls = { # Syscalls
        "alloc":MemoryManager.alloc,
        "free":MemoryManager.free,
        "rwrite":MemoryManager.write,
        "rread":MemoryManager.read,
        "memdump":MemoryManager.dump,
        "memusage":MemoryManager.usage,
        "write":PotatoFileSystem.createFile,
        "read":PotatoFileSystem.getFile,
        }
    
    numericCalls = [
        MemoryManager.alloc,         # Syscall ID #0
        MemoryManager.free,          # Syscall ID #1
        MemoryManager.write,         # Syscall ID #2
        MemoryManager.read,          # Syscall ID #3
        MemoryManager.dump,          # Syscall ID #4
        MemoryManager.usage,         # Syscall ID #5
        PotatoFileSystem.createFile, # Syscall ID #6
        PotatoFileSystem.getFile,    # Syscall ID #7
    ]
    
    def syscaller(syscall,*args,**kwargs): # Faz chamadas do sistema (syscalls)
    # Mexe com as Syscalls
        ret = ""
        try:
            call = int(syscall)
            if call>0:
                if call<len(Kernel.numericCalls):
                    try:
                        ret = Kernel.numericCalls[call](*args, **kwargs)
                    except Exception as e:
                        ret = f"[Python Exception]: {e}"
                raise ValueError(f"Invalid Syscall ID {syscall}")
                
        except:
            if syscall not in Kernel.calls:
                try:
                    raise ValueError(f"Invalid Syscall {syscall}")
                except Exception as e:
                    ret = f"[Python Exception]: {e}"
            ret = Kernel.calls[syscall](*args, **kwargs)
        if len(ret)==0:
            ret = ""
        return ret
    
    def _thread_wrapper(mode: bool, task_name: str, task_func: Callable, *args, **kwargs):
        # Método interno para gerenciar threads com segurança.
        try:
            prefix = "[KERNEL]" if mode else "[USER]"
            print(f"{prefix}: TASK STARTED: {task_name}")
            
            task_func(*args, **kwargs)  # Executa a função
            
        except Exception as e:
            print(f"{prefix}: TASK CRASHED: {task_name} -> {str(e)}")
        finally:
            with Kernel._lock:
                if task_name in Kernel.tasks:
                    del Kernel.tasks[task_name]
            print(f"{prefix}: TASK FINISHED: {task_name}")

    def run(mode: bool, new_thread: bool, task_name: str, task_func: Callable, *args, **kwargs):
        #Executa uma tarefa no modo Kernel ou User, com ou sem thread.
        #
        #Args:
        #    mode: True para Kernel Mode, False para User Mode.
        #    new_thread: Se True, roda em thread separada.
        #    task_name: Nome identificador da tarefa.
        #    task_func: Função a ser executada.
        
        if not callable(task_func):
            print(f"SYSERROR: '{task_func}' IS NOT CALLABLE")
            return

        with Kernel._lock:
            if task_name in Kernel.tasks:
                print(f"[WARNING] Task '{task_name}' is already running!")
                return

            Kernel.tasks[task_name] = (mode, task_func)

        prefix = "[KERNEL]" if mode else "[USER]"
        print(f"{prefix}: LAUNCHING TASK: {task_name}")

        if new_thread:
            thread = threading.Thread(
                target=Kernel._thread_wrapper,
                args=(mode, task_name, task_func, *args),
                kwargs=kwargs,
                daemon=True
            )
            thread.start()
        else:
            Kernel._thread_wrapper(mode, task_name, task_func, *args, **kwargs)

    def dump_running(): # Fala tudo que tá rodando
        """Lista todas as tarefas em execução."""
        with Kernel._lock:
            print(f"\nTasks ({len(Kernel.tasks)}):")
            for task_name, (mode, _) in Kernel.tasks.items():
                print(f"{'[KERNEL]' if mode else '[USER]'}: {task_name}")
    
class SpudScript: # Interpretador SpudScript para PotatOS 
    variables = {
        '!HOME':'//',
        '!USER':'root'
    }
    aliases = {
        '?': 'echo $?',
        'dir': 'ls',
        'rm': 'del',
        'ss': 'script'
    }
    
    def execute(command: str) -> tuple: # Executa um comando SS e retorna (output, exit_code
        command = SpudScript._preprocess(command)
        if not command:
            return ("", 0)
        
        # Substitui aliases
        cmd_parts = command.split(maxsplit=1)
        if cmd_parts[0] in SpudScript.aliases:
            command = SpudScript.aliases[cmd_parts[0]] + (f" {cmd_parts[1]}" if len(cmd_parts) > 1 else "")
        
        # Processa pipelines
        if '|' in command:
            return SpudScript._execute_pipeline(command)
            
        return SpudScript._execute_single(command)
    
    def _preprocess(command: str) -> str: # Preprocessamento do comando
        command = command.strip()
        
        # Substitui variáveis
        if '$' in command and not command.startswith("!!$") and not command.startswith("!$"):
            for var_name in SpudScript.variables:
                command = command.replace(f'$({var_name})', str(SpudScript.variables[var_name]))
                command = command.replace(f'${var_name}', str(SpudScript.variables[var_name]))
        return command
    
    def _execute_single(command: str) -> tuple: # Executa um único comando
        cmd_parts = command.split()
        if not cmd_parts:
            return ("", 0)
            
        base_cmd = cmd_parts[0]
        args = cmd_parts[1:]
        
        # Comandos built-in
        if base_cmd == 'echo':
            return (' '.join(args), 0)
            
        elif base_cmd == 'slap':
            return SpudScript._slap(args)
            
        elif base_cmd == 'if':
            return SpudScript._if_statement(' '.join(args))
            
        elif base_cmd == 'while':
            return SpudScript._while_loop(' '.join(args))
            
        elif base_cmd == 'repeat':
            return SpudScript._repeat(args)
            
        elif base_cmd.startswith('!$'):
            return SpudScript._set_var()
            
        elif base_cmd == 'syscall':
            return SpudScript._syscall(args)
            
        elif base_cmd == 'ls':
            return SpudScript._list_dir(args[0] if args else ".")
            
        elif base_cmd == 'cd':
            return SpudScript._change_dir(args[0] if args else "//")
            
        elif base_cmd.startswith('!!$'):
            return SpudScript._delete_var()
            
        elif base_cmd == 'script':
            return SpudScript._execute_script(args)
            
        else:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}{base_cmd} is not a valid SpudScript command.", 1)
    
    def _slap(args) -> tuple: # Cria arquivos (similar a touch
        if not args:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}slap requires an argument", 1)
        
        try:
            Kernel.PotatoFileSystem.createFile(args[0], [])
            return (f"File '{args[0]}' was sucessfully created", 0)
        except Exception as e:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}slap: {str(e)}", 1)
    
    def _if_statement(SpudScript, condition: str) -> tuple: # Executa um código se <cond> for verdadeiro e outro se for falso.
        parts = condition.split(' then ', 1)
        if len(parts) < 2:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}if: invalid syntax: if <cond> then <cmd> else <cmd> /if", 1)
            
        cond, rest = parts
        if ' else ' in rest:
            then_part, else_part = rest.split(' else ', 1)
        else:
            then_part, else_part = rest, ""
            
        then_part = then_part.rstrip(' /if')
        else_part = else_part.rstrip(' /if')
        
        # Avalia condição (simplificado)
        if SpudScript._eval_condition(cond):
            return SpudScript.execute(then_part)
        elif else_part:
            return SpudScript.execute(else_part)
        return ("", 0)
    
    def _eval_condition(cond: str) -> bool: # Avalia condições simples
        if '==' in cond:
            left, right = cond.split(' == ', 1)
            return str(left) == str(right)
        elif ' exists ' in cond:
            _, path = cond.split(' exists ', 1)
            return os.path.exists(Kernel.PotatoFileSystem.Pythonfy(path))
        return False
    
    def _while_loop(condition: str) -> tuple: # Executa loops até o dia de São Nunca.
        if ' do ' not in condition:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}while: syntax: while <cond> do <cmd> done", 1)
            
        cond, cmd = condition.split(' do ', 1)
        cmd = cmd.rstrip(' done')
        
        output, exit_code = "", 0
        while SpudScript._eval_condition(cond):
            out, code = SpudScript.execute(cmd)
            output += out + "\n"
            exit_code = code
            if code != 0:
                break
        return (output, exit_code)
    
    def _repeat(args) -> tuple: # Repete um comando N vezes
        if len(args) < 2:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}repeat N command", 1)
            
        try:
            times = int(args[0])
            cmd = ' '.join(args[1:])
            
            output, exit_code = "", 0
            for _ in range(times):
                out, code = SpudScript.execute(cmd)
                output += out + "\n"
                exit_code = code
                if code != 0:
                    break
            return (output, exit_code)
        except ValueError:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}repeat: N should be a Number.", 1)
    
    def _set_var() -> tuple: # Define variáveis.
        if '=' not in command:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}!$: syntax: !$var=valor", 1)
            
        cmd = command.replace("!$","")
        var, value = cmd.split('=', 1)
        var = var.strip()
        value = value.strip()
        if var[0] == "!":
            if var in SpudScript.variables:
                return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}!$: {var} is a read-only variable.", 1)
        SpudScript.variables[var] = value
        return ("", 0)
    
    def _syscall(args) -> tuple: # Executa syscalls do Kernel
        if not args:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}syscall: specify a syscall", 1)
            
        try:
            result = Kernel.syscaller(args[0], *args[1:])
            return (str(result), 0)
        except Exception as e:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}syscall: {str(e)}", 1)
    
    def _list_dir(path: str) -> tuple: # Lista diretório
        def _color(items: list):
            txt = ""
            files = []
            folders = []
            for item in items:
                print(item, os.path.isfile(item))
                if os.path.isfile(item):
                    files.append(str(item))
                    print("NEW FILE!", item)
                    print(files)
                else:
                    folders.append(str(item) + "/")
                    print("NEW FOLDER!", item)
                    print(folders)
            for directory in folders:
                txt = f'{txt}{_F.CYAN}{_S.BRIGHT}{directory}\n{_S.RESET_ALL}'
            for file in files:
                txt = f'{txt}{_F.MAGENTA}{_S.BRIGHT}{file}\n{_S.RESET_ALL}'
            return txt
        
        try:
            if len(path)>0:
                return (f"{_F.GREEN}{_S.BRIGHT}{Kernel.PotatoFileSystem.Spudify(".")}\n{_S.RESET_ALL}"+_color(os.listdir()), 0)
            valid, upath = Kernel.PotatoFileSystem.Pythonfy(path)
            if valid:
                return (f"{_F.GREEN}{_S.BRIGHT}{Kernel.PotatoFileSystem.Pythonfy(upath)}\n{_S.RESET_ALL}" + _color(os.listdir(upath)), 0)
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}ls: invalid directory", 1)
        except Exception as e:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}ls: {str(e)}", 1)
    
    def _change_dir(path: str) -> tuple: # Muda de diretório
        try:
            Kernel.PotatoFileSystem.changeDirectory(path)
            return ("", 0)
        except Exception as e:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}cd: {str(e)}", 1)
    
    def _delete_var() -> tuple: # Deleta variáveis: !!$var
        
        cmd = command.replace("!!$","")
        cmd = cmd.strip()
        if cmd in SpudScript.variables:
            if cmd[0] == "!":
                return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}!!$: {var} is a permanent variable.", 1)
            del SpudScript.variables[cmd]
            return ("", 0)
        return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}!!$: {var} was never defined.", 1)
    
    def _execute_pipeline(command: str) -> tuple:   # Executa pipelines de comandos
        commands = command.split('|')
        output, exit_code = "", 0
        
        for cmd in commands:
            output, exit_code = SpudScript.execute(cmd.strip())
            if exit_code != 0:
                break
                
        return (output, exit_code)
        
    def _execute_script(filename: str) -> tuple: # Roda um SpudScript.
        if len(filename)==0:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}script: File not specified.", 1)
        
        try:
            f = Kernel.PotatoFileSystem.getFile(filename)
            if f[0] == "###SpudScript":
                for line in f:
                    line = line.strip()
                    if len(line)>0 and not line.startswith('#'):
                        output, exit_code = SpudScript.execute(line)
                        if len(output)>0:
                            print(output)
                        if exit_code != 0:
                            break
        except FileNotFoundError:
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}script: File not found.", 1)
        except Exception as e:
            traceback.print_exc()
            return (f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}script: error: {str(e)}", 1)

Kernel.MemoryManager.createDisk(1) # 1KB

while True:
    current_dir = Kernel.PotatoFileSystem.Spudify(os.getcwd())
    try:
        command = input(f"{_S.RESET_ALL}{_F.YELLOW}ss {_F.GREEN}{current_dir} {_S.RESET_ALL}$ ")
        if command.lower() in ['exit', 'quit']:
            break
            
        output, exit_code = SpudScript.execute(command)
        if output:
            print(output)
            
        # Define exit code da última operação
        SpudScript.variables['?'] = str(exit_code)
            
    except KeyboardInterrupt:
        print()
    except Exception as e:
        print(f"{_F.RED}{_S.BRIGHT}ss: {_S.NORMAL}error: {str(e)}")
        traceback.print_exc()
        
print("\n-= PotatOS shutdown =-")