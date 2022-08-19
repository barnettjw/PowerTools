Function Get-FileSizeOnDisk() {
    # use cases: compressed files, sparse files, One Drive's Files On Demand
    # source: https://www.opentechguides.com/how-to/article/powershell/133/size-on-disk-ps.html

    param($path)

    $source = @'
 using System;
 using System.Runtime.InteropServices;
 using System.ComponentModel;
 using System.IO;

 namespace Win32
  {
    
    public class Disk {
	
    [DllImport("kernel32.dll")]
    static extern uint GetCompressedFileSizeW([In, MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
    [Out, MarshalAs(UnmanagedType.U4)] out uint lpFileSizeHigh);	
        
    public static ulong GetSizeOnDisk(string filename)
    {
      uint HighOrderSize;
      uint LowOrderSize;
      ulong size;

      FileInfo file = new FileInfo(filename);
      LowOrderSize = GetCompressedFileSizeW(file.FullName, out HighOrderSize);

      if (HighOrderSize == 0 && LowOrderSize == 0xffffffff)
       {
	 throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      else { 
	 size = ((ulong)HighOrderSize << 32) + LowOrderSize;
	 return size;
       }
    }
  }
}
'@

    if (-not ('Win32.Disk' -as [type])) { Add-Type -TypeDefinition $source }

    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $sizeOnDisk = [Win32.Disk]::GetSizeOnDisk($_.FullName) | Out-Null
        if ($sizeOnDisk -eq 0) { $sizeOnDisk = $null }
        $_ | Add-Member -MemberType NoteProperty -Name SizeOnDisk -Value $sizeOnDisk
        
        $_
    } | Select-Object Mode, LastWriteTime, Length, SizeOnDisk, Name
}