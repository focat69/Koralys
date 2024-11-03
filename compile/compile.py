import subprocess
import os

luau_compiler_path = os.path.join("compile", "luau-compile-6.4.4.exe")
luau_compiler_path_599 = os.path.join("compile", "luau-compile-5.exe")
#input_lua = os.path.join("compile", "uselesscode.luau") # Unrecognized constant type: 42
input_lua = os.path.join("compile", "example.luau")
output_bin = os.path.join("compile", "output.luac")

def compile_luau_to_bytecode(input_file, output_file, useversion5=False):
    """
    Compiles a Lua script to bytecode using the Luau compiler and saves it to output_file.
    """
    try:
        if useversion5:
            command = [luau_compiler_path_599, "--binary", "-O0", "-g0", input_file]
        else:
            command = [luau_compiler_path, "--binary", "-O0", "-g0", input_file]
        
        with open(output_file, "wb") as f:
            subprocess.run(command, stdout=f, check=True)
        
        print(f"Compiled {input_file} to {output_file} successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to compile {input_file}: {e}")
    except FileNotFoundError:
        print(f"Luau compiler not found at {luau_compiler_path}. Please check the path.")

compile_luau_to_bytecode(input_lua, output_bin, useversion5=False)