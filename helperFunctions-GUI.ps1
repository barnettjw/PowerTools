function New-Form() {
    param( $width, $height, $title )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Size = New-Object System.Drawing.Size($width, $height)
    $form.Text = $title

    return $form
}
function New-Button() {
    param( $form, $locX, $locY, $sizeX, $sizeY,
        $text, $font = 'Segue UI', $fontSize = 12 )

    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point($locX, $locY)
    $button.Size = New-Object System.Drawing.Size($sizeX, $sizeY)
    $button.Text = $text
    $button.Font = New-Object System.Drawing.Font($font, $fontSize, [System.Drawing.FontStyle]::Regular)
    $form.Controls.Add($button)

    return $button
}

function New-Label() {
    param($locX, $locY, $sizeX, $sizeY, $text)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point($locX, $locY)
    $label.Size = New-Object System.Drawing.Size($sizeX, $sizeY)
    $label.Text = $text
    $form.Controls.Add($label)

    return $label
}

function New-ListBox() {
    param( $width, $height, $locX, $locY, 
        $font = 'Segue UI', $fontSize = 12, 
        [validateset(
            'None', 
            'One', 
            'MultiSimple', 
            'MultiExtended'
        )]$selectionMode 
    )

    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point($locX, $locY)
    $listBox.Width = $width
    $listBox.Height = $height
    
    $listBox.SelectionMode = $selectionMode
    $listBox.Font = New-Object System.Drawing.Font($font, $fontSize, [System.Drawing.FontStyle]::Regular)
}

function New-TreeView() {
    param( $width, $height, $locX, $locY, 
        $itemHeight = 24, $pathSeperator = '.', $checkboxes = $false,
        $font = 'Segue UI', $fontSize = 11 )

    $treeView = New-Object System.Windows.Forms.TreeView
    $treeView.Location = New-Object System.Drawing.Point(30, 30)
    $treeView.Size = New-Object System.Drawing.Size($width, $height)
        
    $treeView.CheckBoxes = $checkboxes
    $treeView.PathSeparator = $pathSeperator 
    $treeView.ItemHeight = $itemHeight
    $treeview.Font = New-Object System.Drawing.Font($font, $fontSize, [System.Drawing.FontStyle]::Regular)
    
    return $treeView
}

Function Get-FileName { 
    # Helper function: wrapper you File Picker UI

    param()
     
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = "$env:userprofile\Downloads"
    $OpenFileDialog.Filter = 'PS1 files (*.ps1|*.ps1|All files (*.*)|*.*'
    $OpenFileDialog.Title = 'Select message to open'
    $OpenFileDialog.ShowDialog() | Out-Null
    
    return $OpenFileDialog.FileName
}

function Get-Icon() {
    # Helper function: extracts an icon from a windows dll or exe file
    
    param($file, $number)
    # Use standard windows icons by extracting from DLL or EXE file
    # from: https://social.technet.microsoft.com/Forums/sqlserver/en-US/16444c7a-ad61-44a7-8c6f-b8d619381a27/using-icons-in-powershell-scripts?forum=winserverpowershell
    
    $iconExtractor = @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;
 
namespace System{
    public class IconExtractor{
        public static Icon Extract(string file, int number, bool largeIcon){
            IntPtr large;
            IntPtr small;
            ExtractIconEx(file, number, out large, out small, 1);
            try{ return Icon.FromHandle(largeIcon ? large : small); }
            catch{ return null; }
        }
        [DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion, out IntPtr piSmallVersion, int amountIcons);
    }
}
'@

    if (-not ('System.IconExtractor' -as [type])) {
        Add-Type -TypeDefinition $iconExtractor -ReferencedAssemblies System.Drawing
    }

    [System.IconExtractor]::Extract($dll, 11, $number)
}

function New-Base64Icon() {
    # Helper function: creates a gui icon from it's base64 representation

    param( $iconBase64 )

    try {
        $iconBytes = [Convert]::FromBase64String($iconBase64)
        $stream = New-Object IO.MemoryStream($iconBytes, 0, $iconBytes.Length)
        $stream.Write($iconBytes, 0, $iconBytes.Length)
        [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap -Argument $stream).GetHIcon())
    }
    catch { }
}

Function Hide-Console {
    # Helper function: hides the PowerShell console window

    if (-not ('Console.Window' -as [type])) {
        Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
    }

    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
}