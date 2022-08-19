function Out-Image() {
    # open image in Powershell GUI window
    
    param($img)

    [void][reflection.assembly]::LoadWithPartialName('System.Windows.Forms')
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object Windows.Forms.Form
    $form.Text = 'Image Viewer'
    $form.WindowState = 'maximized'
    $form.AutoScroll = $true

    $pictureBox = New-Object Windows.Forms.PictureBox
    $pictureBox.Width = $img.Size.Width
    $pictureBox.Height = $img.Size.Height 
    $pictureBox.Image = $img
    $form.controls.add($pictureBox)

    $form.ShowDialog()
}