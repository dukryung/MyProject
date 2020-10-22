$(document).ready(function () {
	//validate 와 val() 값을 동시에 사용하기때문에 selector 의 속도및 자원사용을 줄이기 위한 변수선언;
    //만약 이후 selector 의 이름이 변경 될 경우 아래 selector 의 id 만 변경해 줘도 무방함
    
    var $NewTempletName = $('NewTempletName'),
  $TempletName = $('#TempletName'), 
  $Password = $('#Password'),
  $Verifying_Password = $('#Verifying_Password'),
  $Maximum_ConnectionCount = $('#Maximum_ConnectionCount'),
	$Recv_Buf_Size = $("#Recv_Buf_Size"),
	$Send_Buf_Size = $("#Send_Buf_Size"),
	$Connection_Timeout = $("#Connection_Timeout"),
	$Client_Reconnect_Timeout = $("#Client_Reconnect_Timeout"),
	$Server_Reconnect_Timeout = $("#Server_Reconnect_Timeout"),
	$Limit_Size_Log_Storage = $("#Limit_Size_Log_Storage"),
	$Maxsize_Per_Logfile = $("#Maxsize_Per_Logfile"),
	$Logfile_Path = $("#Logfile_Path"),
	$Err_Logfile_Path = $("#Err_Logfile_Path"),
	$Statistic_Send_Control_Server = $("#Statistic_Send_Control_Server"),
	$Statistic_Collection_Cycle = $("#Statistic_Collection_Cycle"),
	$Statistic_Server_Ip = $("#Statistic_Server_Ip"),
	$Statistic_Server_Port = $("#Statistic_Server_Port"),
	$Statistic_Send_Cycle = $("#Statistic_Send_Cycle"),
	$Bridge_Used = $("#Bridge_Used"),
	$Bridge_Buf_Size = $("#Bridge_Buf_Size"),
	$Encrypt_Mode = $("#Encrypt_Mode"),
	$Change_Client_Ip = $("#Change_Client_Ip"),
  $Node_ID = $("#Node_ID"),
  $KMS_Address = $("#KMS_Address"),
  $KMS_Port = $("#KMS_Port"),
	$Frontendsymbol = $("#Frontend input[Frontendsymbol]"),
	$FrontendPort = $("#Frontend input[FrontendPort]"),
	$BackendIP = $("#Frontend input[BackendIP]"),
    $KMS_Selector = $("#KMS");



	$Password.validate();
	$Maximum_ConnectionCount.validate();
	$Recv_Buf_Size.validate();
	$Send_Buf_Size.validate();
	$Connection_Timeout.validate();
	$Client_Reconnect_Timeout.validate();
	$Server_Reconnect_Timeout.validate();
	$Limit_Size_Log_Storage.validate();
	$Maxsize_Per_Logfile.validate();
	$Logfile_Path.validate();
	$Err_Logfile_Path.validate();
	$Statistic_Collection_Cycle.validate();
	$Statistic_Server_Ip.validate();
	$Statistic_Server_Port.validate();
	$Statistic_Send_Cycle.validate();
	$Bridge_Buf_Size.validate();
	//$Bridge_Used.validate();
	$Encrypt_Mode.validate();
	$Change_Client_Ip.validate();
    $Node_ID.validate();
    $KMS_Address.validate();
    $KMS_Port.validate();
	$Frontendsymbol.validate();
	$FrontendPort.validate();
    $BackendIP.validate(); 

  // if ($Statistic_Send_Control_Server.val() == "Disable") {
  //   $Statistic_Server_Ip.attr("disabled", "disabled"); 
  //   $Statistic_Server_Ip.val('');
  //   $Statistic_Server_Ip.validateRemove();
  //   $Statistic_Server_Port.attr("disabled", "disabled");
  //   $Statistic_Server_Port.val('');
  //   $Statistic_Server_Port.validateRemove();
  //   $Statistic_Send_Cycle.attr("disabled", "disabled");
  //   $Statistic_Send_Cycle.val('');
  //   $Statistic_Send_Cycle.validateRemove();
  // }
//    $Statistic_Server_Ip.attr("disabled", "disabled"); 
 //   $Statistic_Server_Ip.val('');
  //$Statistic_Server_Ip.validateRemove();
//    $Statistic_Server_Port.attr("disabled", "disabled");
//    $Statistic_Server_Port.val('');
  //$Statistic_Server_Port.validateRemove();
//    $Statistic_Send_Cycle.attr("disabled", "disabled");
//    $Statistic_Send_Cycle.val('');
  //$Statistic_Send_Cycle.validateRemove();

  if ($Bridge_Used.val() == "Enable") {
    $Bridge_Buf_Size.attr("disabled","disabled");
    $Bridge_Buf_Size.val('');
    $Bridge_Buf_Size.validateRemove();
  }


$KMS_Selector.on('change',function() {
var KMS_SValue = $('#KMS option:selected').val(),
    KMS_Address = $('#KMS_Address');
    KMS_Address.validateRemove();


if ( KMS_SValue == 'ip' ) {
KMS_Address.attr('reserve','ipv4');
  KMS_Address.attr('min','7');
  KMS_Address.attr('max','15');


}else if ( KMS_SValue == 'domain' ) {
KMS_Address.attr('reserve','url');
KMS_Address.attr('min','');
KMS_Address.attr('max','');

}

KMS_Address.validate();

})

	$($Statistic_Send_Control_Server).on('change',function(){
		var yn = $(this).val();
		//$Statistic_Collection_Cycle.val(yn =="Enable" ? "5" : "");
		//$Statistic_Server_Ip.val(yn =="Enable" ? "100" : "");
		//$Statistic_Server_Port.val(yn =="Enable" ? "5" : "");
		//$Statistic_Send_Cycle.val(yn =="Enable" ? "5" : "");

		if( yn !="Enable"){
		//	$Statistic_Collection_Cycle.attr("disabled", "disabled"); 
	//	$Statistic_Collection_Cycle.validateRemove();
			$Statistic_Server_Ip.attr("disabled", "disabled"); 
			$Statistic_Server_Ip.validateRemove();
			$Statistic_Server_Port.attr("disabled", "disabled"); 
			$Statistic_Server_Port.validateRemove();
			$Statistic_Send_Cycle.attr("disabled", "disabled");
			$Statistic_Send_Cycle.validateRemove();
		}	
		else{
		  //$Statistic_Collection_Cycle.removeAttr("disabled"); 
		  //$Statistic_Collection_Cycle.validate();
			$Statistic_Server_Ip.removeAttr("disabled");
			$Statistic_Server_Ip.validate();
			$Statistic_Server_Port.removeAttr("disabled"); 
			$Statistic_Server_Port.validate();
			$Statistic_Send_Cycle.removeAttr("disabled");	
			$Statistic_Send_Cycle.validate();
		};
	});

	$($Bridge_Used).on('change',function(){
		var yn = $(this).val();
//		$Bridge_Buf_Size.val(yn == "Enable" ? "2097152" : "");
		if (yn =="Enable"){
			$Bridge_Buf_Size.attr("disabled" ,"disabled");
			$Bridge_Buf_Size.validateRemove();
		} else {
			$Bridge_Buf_Size.removeAttr("disabled"); 
			$Bridge_Buf_Size.validate();
		}
	})




	function TransValue() {
		var $Frontdivs = $("#Frontend div[data-siteType=1]");
		var mainArray = [];
    var SymbolArray = [];
    var BindPortArray = [];
    


      for(var i = 0; i<$Frontdivs.length; i++) {
        var $Backdivs =$($Frontdivs[i]).find("div[data-siteType=2] table tr"),
          backendarray = [];

        if($Backdivs.length == 0) {
          alert('Node Mode 를 선택 후 Confirm 버튼을 클릭 하세요');
          return;
        }
        else {
          var $Backend = $($Frontdivs[i]).closest('div[data-SiteType=1]').find('div[data-SiteType=2]')
          if($Backend.attr('Node_mode') != $($Frontdivs[i]).find("select[Node_Mode]").val()) {
            alert('Confirm 버튼을 클릭 하세요');
            return;
          }
        }

        for(var j=0; j<$Backdivs.length; j++){
          var Backobj = { "LAN_interface": $($Backdivs[j]).find("select[LAN_interface]").val(),
            "BackendIP"	   : $.trim($($Backdivs[j]).find("input[BackendIP]").val()),
            "BackendPort"  : $.trim($($Backdivs[j]).find("input[BackendPort]").val())
          };
          backendarray.push(Backobj);
        };

        var Frontobj = { "Frontendsymbol" :  $.trim($($Frontdivs[i]).find("input[Frontendsymbol]").val()),
          "FrontendPort"	  :  $.trim($($Frontdivs[i]).find("input[FrontendPort]").val()),
          "NodeMode"		  :  $($Frontdivs[i]).find("select[Node_Mode]").val(),
          "backend"         :  backendarray
        };
        mainArray.push(Frontobj);

        for(var k=0; k < SymbolArray.length; k++) {
          if(SymbolArray[k] == Frontobj.Frontendsymbol) {
            alert('이미 존재하는 Symbol : '+SymbolArray[k]);
            return;
          }
        }
        SymbolArray[SymbolArray.length] = Frontobj.Frontendsymbol;

        for(var l=0; l < BindPortArray.length; l++) {
          if(BindPortArray[l] == Frontobj.FrontendPort) {
            alert('이미 존재하는Port : '+BindPortArray[l]); 
            return;
          }
        }
        BindPortArray[BindPortArray.length] = Frontobj.FrontendPort; 

        if(Frontobj.NodeMode == "0") {
          alert('Node 모드를 선택해 주세요');
          return;
        }
      };

		var params = {
			"Password": $.trim($Password.val()),
			"VerifyingPassword": $.trim($Verifying_Password.val()),
			"Maximum_ConnectionCount": $.trim($Maximum_ConnectionCount.val()),
			"Recv_Buf_Size": $.trim($Recv_Buf_Size.val()),
			"Send_Buf_Size": $.trim($Send_Buf_Size.val()),
			"Connection_Timeout": $.trim($Connection_Timeout.val()),
			"Client_Reconnect_Timeout": $.trim($Client_Reconnect_Timeout.val()),
			"Server_Reconnect_Timeout": $.trim($Server_Reconnect_Timeout.val()),
			"Limit_Size_Log_Storage": $.trim($Limit_Size_Log_Storage.val()),
			"Maxsize_Per_Logfile": $.trim($Maxsize_Per_Logfile.val()),
			"Logfile_Path": $.trim($Logfile_Path.val()),
			"Err_Logfile_Path": $.trim($Err_Logfile_Path.val()),
			"Statistic_Send_Control_Server": $.trim($Statistic_Send_Control_Server.val()),
			"Statistic_Collection_Cycle": $.trim($Statistic_Collection_Cycle.val()),
			"Statistic_Server_Ip": $.trim($Statistic_Server_Ip.val()),
			"Statistic_Server_Port": $.trim($Statistic_Server_Port.val()),
			"Statistic_Send_Cycle": $.trim($Statistic_Send_Cycle.val()),
			"Bridge_Used": $.trim($Bridge_Used.val()),
      "Bridge_Buf_Size": $.trim($Bridge_Buf_Size.val()),
			"Encrypt_Mode": $.trim($Encrypt_Mode.val()),
			"Change_Client_Ip": $.trim($Change_Client_Ip.val()),
      "Node_ID": $.trim($Node_ID.val()),
      "KMS_Address": $.trim($KMS_Address.val()),
      "KMS_Port": $.trim($KMS_Port.val()),
			"SiteList" : mainArray
		};

    
    
    var current_url = document.location.href;
    var target_url = ""

    target_url = current_url.replace("setting", "update_setting")

		$.ajax({
			url: target_url,
			type: 'POST',
			accepts: { mycustomtype: 'application/x-some-custom-type' },
			data: JSON.stringify(params),
			success: function () {
				alert("저장 완료");
                location.reload();
			},
			error: function () {
				alert("저장 실패");
			}
		});
	};

  function isServerMode() {
    var $Frontdivs = $("#Frontend div[data-siteType=1]");
    var ServerMode = 0;

    for(var i = 0; i<$Frontdivs.length; i++) {
      if($($Frontdivs[i]).find("select[Node_Mode]").val() == 2) {
        return true;
      }
    }

    return false;
  }

  function UpdateChangeIPMode(ServerMode) {
    var $ChangeIPMode = $("#Change_Client_Ip")

    if (ServerMode == 0) {
      $ChangeIPMode.attr("disabled", "disabled"); 
    }
    else if (ServerMode == 1) {
	  $ChangeIPMode.removeAttr("disabled"); 
    }
  }

  function ChoiceTempletName(){
    var $TempletName = $("#TempletName")
      if (confirm('TemplateName : '+ $TempletName.val()+ '를 불러오시겠습니까?')) {
        TransTempletNameforload()
    }
  }
  
  function DeleteTemplet(){
    var $TempletName = $("#TempletName")
    var $Node_ID = $("#Node_ID")
   
    
    if ($TempletName.val() == "New") {
        alert('TemplateName : '+ $TempletName.val()+ "는 지울 수 없습니다.")
        location.reload();
    } else {
      if (confirm('TemplateName : '+ $TempletName.val()+ '를 삭제 진행하시겠습니까?')) {
        TransTempletNameforDelete()   
        }
    }
  }
  function Canceltemplet(){
    if (confirm('설정된 값이 삭제됩니다, 진행하시겠습니까?')) {
      location.reload()
    }

  }

  function  SaveNewTemplet(){
    var $NewTempletName = $("#NewTempletName") 
    if ($NewTempletName.val() !="" ) {
      TransNewTempletInfo();          
    } else {
      alert("입력란에 생성 이름을 입력하세요. ")        
    }
  }
  function  SaveTemplet(){
    var $TempletName = $("#TempletName") 
    if ($TempletName.val() !="New") {
      ModifiedTempletInfo();          
    } else {
      alert("새로운 Templet 저장 시, save as 버튼을 눌러주세요.")        
    }
  }


  function TransTempletNameforload() {
   
        $("#TempletName option:selected").val();
        var addr = "/load_cfg_templet/"
        str = location.href;
        lastidx = str.lastIndexOf("/add_cfg_templet");
        url = str.substring(0,lastidx+1);
        currenturl= addr+"?TempletName=" + $("#TempletName option:selected").val();
        location.href=currenturl
  }

  function TransTempletNameforDelete() {
   
    $("#TempletName option:selected").val();
    var addr = "/delete_cfg_templet/"
    str = location.href;
    lastidx = str.lastIndexOf("/add_cfg_templet");
    url = str.substring(0,lastidx+1);
    currenturl= addr+"?TempletName=" + $("#TempletName option:selected").val();
    location.href=currenturl
}

  function TransNewTempletInfo() {
    var $Frontdivs = $("#Frontend div[data-siteType=1]");
		var mainArray = [];
    var SymbolArray = [];
    var BindPortArray = [];   

      for(var i = 0; i<$Frontdivs.length; i++) {
        var $Backdivs =$($Frontdivs[i]).find("div[data-siteType=2] table tr"),
          backendarray = [];

        if($Backdivs.length == 0) {
          alert('Node Mode 를 선택 후 Confirm 버튼을 클릭 하세요');
          return;
        }
        else {
          var $Backend = $($Frontdivs[i]).closest('div[data-SiteType=1]').find('div[data-SiteType=2]')
          if($Backend.attr('Node_mode') != $($Frontdivs[i]).find("select[Node_Mode]").val()) {
            alert('Confirm 버튼을 클릭 하세요');
            return;
          }
        }

        for(var j=0; j<$Backdivs.length; j++){          
          var Backobj = { "LAN_interface": $($Backdivs[j]).find("select[LAN_interface]").val(),
            "BackendIP"	   : $.trim($($Backdivs[j]).find("input[BackendIP]").val()),            
            "BackendPort"  : $.trim($($Backdivs[j]).find("input[BackendPort]").val())
          };
          backendarray.push(Backobj);
        };

        var Frontobj = { "Frontendsymbol" :  $.trim($($Frontdivs[i]).find("input[Frontendsymbol]").val()),
          "FrontendPort"	  :  $.trim($($Frontdivs[i]).find("input[FrontendPort]").val()),
          "NodeMode"		  :  $($Frontdivs[i]).find("select[Node_Mode]").val(),
          "backend"         :  backendarray
        };
        mainArray.push(Frontobj);

        for(var k=0; k < SymbolArray.length; k++) {
          if(SymbolArray[k] == Frontobj.Frontendsymbol) {
            alert('이미 존재하는 Symbol : '+SymbolArray[k]);
            return;
          }
        }
        SymbolArray[SymbolArray.length] = Frontobj.Frontendsymbol;

        for(var l=0; l < BindPortArray.length; l++) {
          if(BindPortArray[l] == Frontobj.FrontendPort) {
            alert('이미 존재하는Port : '+BindPortArray[l]); 
            return;
          }
        }
        BindPortArray[BindPortArray.length] = Frontobj.FrontendPort; 

        if(Frontobj.NodeMode == "0") {
          alert('Node 모드를 선택해 주세요');
          return;
        }
      };
      
		var Params = {
      "NewTempletName": $.trim($("#NewTempletName").val()),
			"Password": $.trim($Password.val()),
			"VerifyingPassword": $.trim($Verifying_Password.val()),
			"Maximum_ConnectionCount": $.trim($Maximum_ConnectionCount.val()),
			"Recv_Buf_Size": $.trim($Recv_Buf_Size.val()),
			"Send_Buf_Size": $.trim($Send_Buf_Size.val()),
			"Connection_Timeout": $.trim($Connection_Timeout.val()),
			"Client_Reconnect_Timeout": $.trim($Client_Reconnect_Timeout.val()),
			"Server_Reconnect_Timeout": $.trim($Server_Reconnect_Timeout.val()),
			"Limit_Size_Log_Storage": $.trim($Limit_Size_Log_Storage.val()),
			"Maxsize_Per_Logfile": $.trim($Maxsize_Per_Logfile.val()),
			"Logfile_Path": $.trim($Logfile_Path.val()),
			"Err_Logfile_Path": $.trim($Err_Logfile_Path.val()),
			"Statistic_Send_Control_Server": $.trim($Statistic_Send_Control_Server.val()),
			"Statistic_Collection_Cycle": $.trim($Statistic_Collection_Cycle.val()),
			"Statistic_Server_Ip": $.trim($Statistic_Server_Ip.val()),
			"Statistic_Server_Port": $.trim($Statistic_Server_Port.val()),
			"Statistic_Send_Cycle": $.trim($Statistic_Send_Cycle.val()),
			"Bridge_Used": $.trim($Bridge_Used.val()),
      "Bridge_Buf_Size": $.trim($Bridge_Buf_Size.val()),
			"Encrypt_Mode": $.trim($Encrypt_Mode.val()),
			"Change_Client_Ip": $.trim($Change_Client_Ip.val()),
      "KMS_Address": $.trim($KMS_Address.val()),
      "KMS_Port": $.trim($KMS_Port.val()),
			"SiteList" : mainArray
		};

    var current_url = document.location.href;
    var target_url = ""

    if (current_url.indexOf("add_cfg_templet") !=-1) {
      var url_arr = current_url.split("add_cfg_templet")
      target_url = url_arr[0]+ "save_cfg_newtemplet/"

    } else if (current_url.indexOf("load_cfg_templet")!=-1) {
      var url_arr = current_url.split("load_cfg_templet")
      target_url = url_arr[0]+ "save_cfg_newtemplet/"
      alert(target_url)
    } 
    
   $.ajax({
    url: target_url,
    type: 'POST',
    contentType: 'application/json; charset=UTF-8',
    data: JSON.stringify(Params),
    success: function () {
      alert("저장 완료");
      if (current_url.indexOf("add_cfg_templet") !=-1) {
        var url_arr = current_url.split("add_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
  
      } else if (current_url.indexOf("load_cfg_templet")!=-1) {
        var url_arr = current_url.split("load_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
        alert(target_url)
      }  
      location.href = target_url
    },
    error: function () {
      alert("저장 실패");
      if (current_url.indexOf("add_cfg_templet") !=-1) {
        var url_arr = current_url.split("add_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
  
      } else if (current_url.indexOf("load_cfg_templet")!=-1) {
        var url_arr = current_url.split("load_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
        alert(target_url)
      }  
      location.href = target_url
    }
  });
  }
  function ModifiedTempletInfo() {
    var $Frontdivs = $("#Frontend div[data-siteType=1]");
		var mainArray = [];
    var SymbolArray = [];
    var BindPortArray = [];   

      for(var i = 0; i<$Frontdivs.length; i++) {
        var $Backdivs =$($Frontdivs[i]).find("div[data-siteType=2] table tr"),
          backendarray = [];

        if($Backdivs.length == 0) {
          alert('Node Mode 를 선택 후 Confirm 버튼을 클릭 하세요');
          return;
        }
        else {
          var $Backend = $($Frontdivs[i]).closest('div[data-SiteType=1]').find('div[data-SiteType=2]')
          if($Backend.attr('Node_mode') != $($Frontdivs[i]).find("select[Node_Mode]").val()) {
            alert('Confirm 버튼을 클릭 하세요');
            return;
          }
        }

        for(var j=0; j<$Backdivs.length; j++){
          var Backobj = { "LAN_interface": $($Backdivs[j]).find("select[LAN_interface]").val(),
            "BackendIP"	   : $.trim($($Backdivs[j]).find("input[BackendIP]").val()),
            "BackendPort"  : $.trim($($Backdivs[j]).find("input[BackendPort]").val())
          };
          backendarray.push(Backobj);
        };

        var Frontobj = { "Frontendsymbol" :  $.trim($($Frontdivs[i]).find("input[Frontendsymbol]").val()),
          "FrontendPort"	  :  $.trim($($Frontdivs[i]).find("input[FrontendPort]").val()),
          "NodeMode"		  :  $($Frontdivs[i]).find("select[Node_Mode]").val(),
          "backend"         :  backendarray
        };
        mainArray.push(Frontobj);

        for(var k=0; k < SymbolArray.length; k++) {
          if(SymbolArray[k] == Frontobj.Frontendsymbol) {
            alert('이미 존재하는 Symbol : '+SymbolArray[k]);
            return;
          }
        }
        SymbolArray[SymbolArray.length] = Frontobj.Frontendsymbol;

        for(var l=0; l < BindPortArray.length; l++) {
          if(BindPortArray[l] == Frontobj.FrontendPort) {
            alert('이미 존재하는Port : '+BindPortArray[l]); 
            return;
          }
        }
        BindPortArray[BindPortArray.length] = Frontobj.FrontendPort; 

        if(Frontobj.NodeMode == "0") {
          alert('Node 모드를 선택해 주세요');
          return;
        }
      };
      $("#TempletName option:selected").val();
		var Params = {
      "TempletName": $.trim($("#TempletName option:selected").val()),
			"Password": $.trim($Password.val()),
			"VerifyingPassword": $.trim($Verifying_Password.val()),
			"Maximum_ConnectionCount": $.trim($Maximum_ConnectionCount.val()),
			"Recv_Buf_Size": $.trim($Recv_Buf_Size.val()),
			"Send_Buf_Size": $.trim($Send_Buf_Size.val()),
			"Connection_Timeout": $.trim($Connection_Timeout.val()),
			"Client_Reconnect_Timeout": $.trim($Client_Reconnect_Timeout.val()),
			"Server_Reconnect_Timeout": $.trim($Server_Reconnect_Timeout.val()),
			"Limit_Size_Log_Storage": $.trim($Limit_Size_Log_Storage.val()),
			"Maxsize_Per_Logfile": $.trim($Maxsize_Per_Logfile.val()),
			"Logfile_Path": $.trim($Logfile_Path.val()),
			"Err_Logfile_Path": $.trim($Err_Logfile_Path.val()),
			"Statistic_Send_Control_Server": $.trim($Statistic_Send_Control_Server.val()),
			"Statistic_Collection_Cycle": $.trim($Statistic_Collection_Cycle.val()),
			"Statistic_Server_Ip": $.trim($Statistic_Server_Ip.val()),
			"Statistic_Server_Port": $.trim($Statistic_Server_Port.val()),
			"Statistic_Send_Cycle": $.trim($Statistic_Send_Cycle.val()),
			"Bridge_Used": $.trim($Bridge_Used.val()),
      "Bridge_Buf_Size": $.trim($Bridge_Buf_Size.val()),
			"Encrypt_Mode": $.trim($Encrypt_Mode.val()),
			"Change_Client_Ip": $.trim($Change_Client_Ip.val()),
      "KMS_Address": $.trim($KMS_Address.val()),
      "KMS_Port": $.trim($KMS_Port.val()),
			"SiteList" : mainArray
		};

    var current_url = document.location.href;
    var target_url = ""

    if (current_url.indexOf("add_cfg_templet") !=-1) {
      var url_arr = current_url.split("add_cfg_templet")
      target_url = url_arr[0]+ "modified_cfg_templet/"

    } else if (current_url.indexOf("load_cfg_templet")!=-1) {
      var url_arr = current_url.split("load_cfg_templet")
      target_url = url_arr[0]+ "modified_cfg_templet/"
    }  
 
   // target_url = current_url.replace("setting", "update_setting")
    
   $.ajax({
    url: target_url,
    type: 'POST',
    contentType: 'application/json; charset=UTF-8',
    data: JSON.stringify(Params),
   success:
    function () {
      alert("저장 완료");
      if (current_url.indexOf("add_cfg_templet") !=-1) {
        var url_arr = current_url.split("add_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
  
      } else if (current_url.indexOf("load_cfg_templet")!=-1) {
        var url_arr = current_url.split("load_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
        alert(target_url)
      }  
      location.href = target_url
    },
    error: 
    function () {
      alert("저장 실패");
      if (current_url.indexOf("add_cfg_templet") !=-1) {
        var url_arr = current_url.split("add_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
  
      } else if (current_url.indexOf("load_cfg_templet")!=-1) {
        var url_arr = current_url.split("load_cfg_templet")
        target_url = url_arr[0]+ "add_cfg_templet/"
        alert(target_url)
      }  
      location.href = target_url
    }
  });



  /*
		$.ajax({
			url: target_url,
			type: 'POST',
			datatype : "JSON" ,
			data: JSON.stringify(params),
			success: function () {
				alert("저장 완료");
        location.reload();
			},
			error: function () {
				alert("저장 실패");
			}
		});
*/
/*
    var current_url = document.location.href;
    var target_url = ""
    var url_arr = current_url.split("add_cfg_templet")
    target_url = url_arr[0]+ "save_cfg_newtemplet"
    //target_url = current_url.replace("add_cfg_templet", "save_cfg_newtemplet")
    alert(target_url)
		$.ajax({
			url: target_url,
			type: 'POST',
			accepts: { mycustomtype: 'application/x-some-custom-type' },
      data: JSON.stringify(params),
      complete: function (response, textStatus) {
        if (response.status == "200") {
            var jsonObject = JSON.parse(response.responseText);
            if (jsonObject.Result == "Succ") {
              alert("New Templet 저장을 완료했습니다. (NewTempletName : " +  $TempletName +")" )
              location.reload();
            } else {
              alert("New Templet 저장을 실패했습니다. (NewTempletName : " +  $TempletName +")" )
            }
        } else {
            alert("Failed Save");
        }        
			},
			error: function () {
        alert("Error Save");
      }      
    });  
    */    
};
  

	//페이지가 준비가 완료 되면 Frontend 의 이벤트를 걸어준다
	$('#main button[act]').on('click', function (e) {
		e.preventDefault();
		var act = $(this).attr('act');
		if (act == 'btnFrontendAdd') { //add Frontend
			bindFrontend();
		}
		else if (act == 'btnFrontEndRemove') { //frontend 삭제
			$(this).closest('div[data-SiteType=1]').remove();
		}
		else if (act == 'btnFrontendConfirm') { // add backoffice
          var $Backend = $(this).closest('div[data-SiteType=1]').find('div[data-SiteType=2]')
          var $SelectNumber = Number($(this).closest('td').find('select option:selected').val())

            UpdateChangeIPMode(isServerMode())

          if ($SelectNumber > 0)  {
            if (isEmpty($Backend) == false) {
              if ($Backend.attr('Node_mode') != $SelectNumber) {
                if (confirm('설정된 값이 삭제됩니다, 진행하시겠습니까?')) {
                  $Backend.remove();
                  bindBackOffice($(this), Number($(this).closest('td').find('select option:selected').val()));
                }
              }
            }
            else {
              bindBackOffice($(this), Number($(this).closest('td').find('select option:selected').val()));
            }
          }
          else {
              alert('Node 모드를 선택해 주세요');
          };
      }
      else if (act == "btnSave") {
          $.validator.check(function () {
              TransValue();
          }, 'all');        
      }
      else if (act == "btnTempletEdit") {
            ChoiceTempletName();
      }
      else if (act == "btnTempletDelete") {
      DeleteTemplet();
      }
      else if (act == "btnTempletsaveas") {
        $.validator.check(function () {
        SaveNewTemplet();
      }, 'all');  
      }
      else if (act == "btnTempletcancel") {
      Canceltemplet();
      }      
      else if (act == "btnTempletsave") {
        SaveTemplet();
      }
      else if (act =="btnCancel")  {
        location.reload();
      }
      else if (act == "btnBackEndAdd") {
        bindAddServerList($(this));
      }
      else if (act == "btnBackEndDelete") {
        var $tr = $(this).closest('div[data-SiteType=2]').find('table tbody tr');
        if ($tr.length > 1) {
          $tr.last().remove();
        }        
        else {
          alert('최소 1개의 Server 는 있어야 합니다.');
        };
      };
    });

  function isEmpty(value) {
    if(value == ""||value == null||value == undefined||value.length==0){
      return true
    } else {
      return false
    }
  };


	//frontend 를 바인딩
	function bindFrontend() {
		//바인딩
		var bind = $('#tmplFrontend').tmpl().appendTo($('#Frontend'));
		
		$('input[Frontendsymbol]', bind).validate();
		$('input[FrontendPort]', bind).validate();
		//$('#Node_Mode', bind).validate();

		//바인딩한 데이터에 이벤트를 걸어준다.
		$('button[act]', bind).on('click', function () {
			var act = $(this).attr('act');

			if (act == 'btnFrontEndRemove') { // frontend 삭제
				$(this).closest('div[data-SiteType=1]').remove();
			}
			else if (act == 'btnFrontendConfirm') {// 컨펌 이벤트				
              var $Backend = $(this).closest('div').find('div[data-SiteType=2]')
              var $SelectNumber = Number($(this).closest('td').find('select option:selected').val())
            
              UpdateChangeIPMode(isServerMode())

                if ($SelectNumber > 0)  {
                  if (isEmpty($Backend) == false) {
                    if ($Backend.attr('Node_mode') != $SelectNumber) {
                      if (confirm('설정된 값이 삭제됩니다, 진행하시겠습니까?')) {
                        $Backend.remove();
                        bindBackOffice($(this), Number($(this).closest('td').find('select option:selected').val()));
                      }
                    }
                  }
                  else {
                    bindBackOffice($(this), Number($(this).closest('td').find('select option:selected').val()));
                  }
				}
				else {
					alert('Node 모드를 선택해 주세요');
				};
			};
		});
	};

	//Backoffice 바인딩
	function bindBackOffice($this, num) {
		var bind = $(num == 1 ? "#Backend" : num > 1 ? "#Backend" + num : "#Backend").tmpl().appendTo($this.closest('div[data-SiteType=1]'));
		//바인딩한 데이터에 이벤트를 걸어준다.
		$('input[BackendIP]',bind).validate();
		$('input[BackendPort]',bind).validate();

		$('button[act]', bind).on('click', function () {
			var act = $(this).attr('act');
			if (act == 'btnBackEndAdd') { //서버 추가
				bindAddServerList($(this));
			}
			else if (act == 'btnBackEndDelete') { //서버 삭제
				var $tr = $(this).closest('div[data-SiteType=2]').find('table tbody tr');
				if ($tr.length > 1) {
					$tr.last().remove();
				}
				else {
					alert('최소 1개의 Server 는 있어야 합니다.');
				};
			};
		});
	};

	//서버 리스트 바인딩
	function bindAddServerList($this) {
	 var bind =$('#tmplBackendServerList').tmpl().appendTo($this.closest('div[data-SiteType=2]').find('table'));
	 $('input[BackendIP]',bind).validate();
  	 $('input[BackendPort]',bind).validate();
	};
              
  UpdateChangeIPMode(isServerMode())
});

