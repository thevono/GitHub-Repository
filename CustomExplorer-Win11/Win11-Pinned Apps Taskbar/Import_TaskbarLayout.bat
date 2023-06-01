
MD C:\Windows\EndpointApps
MD C:\Windows\EndpointApps\Win-Custom

COPY "%~dp0taskbar-layout.xml" C:\Windows\EndpointApps\Win-Custom /Y

Import-StartLayout -LayoutPath "C:\Windows\EndpointApps\Win-Custom\taskbar-layout.xml" -MountPath $env:SystemDrive\
