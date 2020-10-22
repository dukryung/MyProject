﻿; Script generated by the HM NIS Edit Script Wizard.

Unicode true
; HM NIS Edit Wizard helper defines
!define PRODUCT_DIR "."
!define PRODUCT_OEM_DIR "svc_corporation"
!define PRODUCT_NAME "svc_node"
!define PRODUCT_EXE_NAME "${PRODUCT_NAME}.exe"
!define PRODUCT_VERSION "1.1"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\${PRODUCT_EXE_NAME}"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

;StatWebServer defines
!define STAT_PRODUCT_NAME "Stat_Web_windows"
!define STAT_PRODUCT_EXE_NAME "${STAT_PRODUCT_NAME}.exe"

; MUI 1.67 compatible ------
;!include "MUI.nsh"

;!include "/root/go/src/MCS_KMS_Create_Pkg/Package_tools/Windows/NSIS/Include/MUI.nsh"
!include ".\MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "Korean"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${PRODUCT_NAME}.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_OEM_DIR}"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
  SetOutPath "$INSTDIR\pages"
  SetOverwrite try
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\app.js"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Control_Login.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Control_Node_Client_Statistics.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Control_Node_Server_Statistics.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\jquery.tmpl.js"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\jquery.validate.js"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\jquery-3.4.1.min.js"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Login.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Node_Client_Statistics.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Node_Server_Statistics.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Node_Setting.html"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\Node_Setting.html.js"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\styles.css"
  
  SetOutPath "$INSTDIR\pages\css"
  SetOverwrite try  
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\base.css"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\common.css"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\common.less"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\contents.css"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\contents.less"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\fontium.css"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\css\jquery.validate.css"

  SetOutPath "$INSTDIR\pages\images\img"
  SetOverwrite try
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\bullet_h1.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\bullet_lnb.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\bullet_path.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\dot.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\login_input.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\login_logo.gif"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\pages\images\img\vline_topmenu.gif"  

  SetOutPath "$INSTDIR\db"
  SetOverwrite try
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\db\traffic.db"

  SetOutPath "$INSTDIR"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\Stat_install.cmd"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\${STAT_PRODUCT_EXE_NAME}"  
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\Stat_uninstall.cmd"
  
  SetOutPath "$INSTDIR\cfg"
  SetOverwrite try
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\cfg\app.cfg"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\cfg\userkey.key"
  SetOutPath "$INSTDIR"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\install.cmd"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\${PRODUCT_EXE_NAME}"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  File "${PRODUCT_DIR}\${PRODUCT_OEM_DIR}\uninstall.cmd"
  CreateDirectory "$INSTDIR\logs"

  DetailPrint "Install Windows Stat Service"
  ExecWait "$INSTDIR\Stat_install.cmd ${STAT_PRODUCT_NAME}"
   DetailPrint "Firewall..."
  ExecWait 'netsh advfirewall firewall add rule name=${STAT_PRODUCT_NAME} dir=in action=allow program="$INSTDIR\${STAT_PRODUCT_EXE_NAME}" enable=yes profile=public,private'

  DetailPrint "Install Windows Service..."
  ExecWait "$INSTDIR\install.cmd ${PRODUCT_NAME}"
  DetailPrint "Firewall..."
  ExecWait 'netsh advfirewall firewall add rule name=${PRODUCT_NAME} dir=in action=allow program="$INSTDIR\${PRODUCT_EXE_NAME}" enable=yes profile=public,private'
  SectionEnd

Section -AdditionalIcons
  CreateShortCut "$SMPROGRAMS\${PRODUCT_OEM_DIR}\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\${PRODUCT_EXE_NAME}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\${PRODUCT_EXE_NAME}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
SectionEnd


Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name)는(은) 완전히 제거되었습니다."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "$(^Name)을(를) 제거하시겠습니까?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  DetailPrint "Uninstall Windows  Stat Service..."
  ExecWait "$INSTDIR\Stat_uninstall.cmd ${STAT_PRODUCT_NAME}"
  Sleep 3000  
  DetailPrint "Uninstall Windows Service..."
  ExecWait "$INSTDIR\uninstall.cmd ${PRODUCT_NAME}"
  Sleep 3000
  ExecWait 'netsh advfirewall firewall delete rule name=${PRODUCT_NAME}'

  Delete "$INSTDIR\pages\app.js"
  Delete "$INSTDIR\pages\Control_Login.html"
  Delete "$INSTDIR\pages\Control_Node_Client_Statistics.html"
  Delete "$INSTDIR\pages\Control_Node_Server_Statistics.html"
  Delete "$INSTDIR\pages\jquery.tmpl.js"
  Delete "$INSTDIR\pages\jquery.validate.js"
  Delete "$INSTDIR\pages\jquery-3.4.1.min.js"
  Delete "$INSTDIR\pages\Login.html"
  Delete "$INSTDIR\pages\Node_Client_Statistics.html"
  Delete "$INSTDIR\pages\Node_Server_Statistics.html"
  Delete "$INSTDIR\pages\Node_Setting.html"
  Delete "$INSTDIR\pages\Node_Setting.html.js"
  Delete "$INSTDIR\pages\styles.css"

  Delete "$INSTDIR\pages\css\base.css"
  Delete "$INSTDIR\pages\css\common.css"
  Delete "$INSTDIR\pages\css\common.less"
  Delete "$INSTDIR\pages\css\contents.css"
  Delete "$INSTDIR\pages\css\contents.less"
  Delete "$INSTDIR\pages\css\fontium.css"
  Delete "$INSTDIR\pages\css\jquery.validate.css"

  Delete "$INSTDIR\pages\images\img\bullet_h1.gif"
  Delete "$INSTDIR\pages\images\img\bullet_lnb.gif"
  Delete "$INSTDIR\pages\images\img\bullet_path.gif"
  Delete "$INSTDIR\pages\images\img\dot.gif"
  Delete "$INSTDIR\pages\images\img\login_input.gif"
  Delete "$INSTDIR\pages\images\img\login_logo.gif"
  Delete "$INSTDIR\pages\images\img\vline_topmenu.gif"  

  Delete "$INSTDIR\Stat_uninstall.cmd" 
  Delete "$INSTDIR\${STAT_PRODUCT_EXE_NAME}"
  Delete "$INSTDIR\Stat_install.cmd"

  Delete "$INSTDIR\db\traffic.db"

  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\uninstall.cmd"
  Delete "$INSTDIR\${PRODUCT_EXE_NAME}"
  Delete "$INSTDIR\install.cmd"
  Delete "$INSTDIR\cfg\app.cfg"
  Delete "$INSTDIR\cfg\userkey.key"

  Delete "$SMPROGRAMS\${PRODUCT_OEM_DIR}\Uninstall.lnk"
  Delete "$DESKTOP\${PRODUCT_OEM_DIR}.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_OEM_DIR}\${PRODUCT_NAME}.lnk"
    
  RMDir "$INSTDIR\pages\css"
  RMDir "$INSTDIR\pages\images\img"
  RMDir "$INSTDIR\pages\images"
  RMDir "$INSTDIR\pages"
  RMDir "$INSTDIR\db"
  
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  RMDir "$INSTDIR\cfg"
  RMDir "$INSTDIR"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd
