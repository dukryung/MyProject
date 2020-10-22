$(document).ready(function () {
	//validate 와 val() 값을 동시에 사용하기때문에 selector 의 속도및 자원사용을 줄이기 위한 변수선언;
	//만약 이후 selector 의 이름이 변경 될 경우 아래 selector 의 id 만 변경해 줘도 무방함
	var $Password = $('#Password'),
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
  //$Node_ID.validate();
    $KMS_Address.validate();
    $KMS_Port.validate();
	$Frontendsymbol.validate();
	$FrontendPort.validate();
    $BackendIP.validate(); 

  if ($Statistic_Send_Control_Server.val() == "Disable") {
    $Statistic_Server_Ip.attr("disabled", "disabled"); 
    //$Statistic_Server_Ip.val('');
    $Statistic_Server_Ip.validateRemove();
    $Statistic_Server_Port.attr("disabled", "disabled");
    //$Statistic_Server_Port.val('');
    $Statistic_Server_Port.validateRemove();
    $Statistic_Send_Cycle.attr("disabled", "disabled");
    //$Statistic_Send_Cycle.val('');
    $Statistic_Send_Cycle.validateRemove();
  }

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


} else if ( KMS_SValue == 'domain' ) {
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


  function ProvisioningUploadRequest(data) {    
    
    $.ajax({
      async: false,
      url: "/provisioning_upload/",
      timeout:5000,
      type: "POST",
      dataType: "json",
      contentType: 'application/json; charset=UTF-8',
      data: JSON.stringify(data),
      complete: 
        function (response, textStatus) {
          var jsonObject = JSON.parse(response.responseText);

          if (response.status == "200") {            
            if (jsonObject.code == "200") {
              alert("저장 성공")
              $(location).attr('href',document.location.href);  

            } else {
              alert("저장 실패")
              alert("code : " + jsonObject.code)
              alert("message : " + jsonObject.message)
            }   
          } else {
            alert("저장 실패")
            alert("code : " + jsonObject.code)
            alert("message : " + jsonObject.message)
          }
        },
      error: 
        function(xml_request, text_status, error_thrown) {
          alert("오류발생\n(Network 상태를 확인하여 주시기 바랍니다.)");
        },      
  });
  }


	function TransValue() {
		var $Frontdivs = $("#Frontend div[data-siteType=1]");
		var mainArray = [];
    var SymbolArray = [];
    var BindPortArray = [];    
    var Version = "";
    var Method = ""; 
    var SessionType = "";
    var MessageType =  "";
    var RemoteURL = "";
    var UserKeyInputValue = "";
    var UserKeyEncodeValue = "";
    var NodeIDInputValue = "";
    var NodeIDEncodeValue = "";
    var UserKeyIDValue = "";
    var UserKeyIDEncodeValue = "";
    var DeviceIDValue = "";
    var DeviceIDEncodeValue = "";
    var MacTotalvalue = "";
    var CurrentSeqValue;
    var NextSeqValue;
    var AuthKeyReturnValue = "";
    var AuthTokenReturnValue = "";
    var ConfigRequestData = "";
		var FrontendArray = [];
		var BackendArray = [];
    
    for(var i = 0; i<$Frontdivs.length; i++) {
      var $Backdivs =$($Frontdivs[i]).find("div[data-siteType=2] table tr"),
        backendarray = [];
        if  (checkSpace($.trim($($Frontdivs[i]).find("input[Frontendsymbol]").val())) == true) {
          alert('Frontend의 Symbol에서 공백을 제거하세요');
          return;
  
        }

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
        var Backobj = { 
          "nic": $($Backdivs[j]).find("select[LAN_interface]").val(),
          "server_ip"	   : $.trim($($Backdivs[j]).find("input[BackendIP]").val()),
          "server_port"  : $.trim($($Backdivs[j]).find("input[BackendPort]").val())
        };
        backendarray.push(Backobj);
      };

      var Frontobj = { 
        "name" :  $.trim($($Frontdivs[i]).find("input[Frontendsymbol]").val()),
        "bind"	  :  $.trim($($Frontdivs[i]).find("input[FrontendPort]").val()),
        "node_mode"		  :  $($Frontdivs[i]).find("select[Node_Mode]").val(),
        "backend"         :  backendarray
      };
      mainArray.push(Frontobj);
      
      for(var k=0; k < SymbolArray.length; k++) {
        if(SymbolArray[k] == Frontobj.name) {
          alert("'" + Frontobj.name + "' " + 'Frontend Symbol\n이미 존재합니다.');
          return;
        }
      }
      
      SymbolArray[SymbolArray.length] = Frontobj.name;
      for(var l=0; l < BindPortArray.length; l++) {
        if(BindPortArray[l] == Frontobj.bind) {
          alert("'" + Frontobj.bind + "' " + 'Frontend bind Port\n이미 존재합니다.');
          return;
        }
      }
      BindPortArray[BindPortArray.length] = Frontobj.bind; 

      if(Frontobj.node_mode == "0") {
        alert('Node 모드를 선택해 주세요');
        return;
      }
    };

    var params = {
      "password": $.trim($Password.val()),
      "verif_password": $.trim($Verifying_Password.val()),
      "max_conn": $.trim($Maximum_ConnectionCount.val()),
      "recv_buffer_size": $.trim($Recv_Buf_Size.val()),
      "send_buffer_size": $.trim($Send_Buf_Size.val()),
      "timeout_connect": $.trim($Connection_Timeout.val()),
      "timeout_client": $.trim($Client_Reconnect_Timeout.val()),
      "timeout_server": $.trim($Server_Reconnect_Timeout.val()),
      "disk_limit": $.trim($Limit_Size_Log_Storage.val()),
      "max_size": $.trim($Maxsize_Per_Logfile.val()),
      "log_path": $.trim($Logfile_Path.val()),
      "err_path": $.trim($Err_Logfile_Path.val()),
      "stat_send_ctrl_srv": $.trim($Statistic_Send_Control_Server.val()),
      "stat_coll_cycle": $.trim($Statistic_Collection_Cycle.val()),
      "stat_server_ip": $.trim($Statistic_Server_Ip.val()),
      "stat_server_port": $.trim($Statistic_Server_Port.val()),
      "stat_data_send_cycle": $.trim($Statistic_Send_Cycle.val()),
      "node_bridage": $.trim($Bridge_Used.val()),
      "node_buffer_size": $.trim($Bridge_Buf_Size.val()),
      "encrypt": $.trim($Encrypt_Mode.val()),
      "ip_client_mode": $.trim($Change_Client_Ip.val()),
      "nodeid": $.trim($Node_ID.val()),
      "kms_ip": $.trim($KMS_Address.val()),
      "kms_port": $.trim($KMS_Port.val()),
      "frontend" : mainArray
    };
    
    document.getElementById("PV_ResponseCode").value = ""
    document.getElementById("PV_ResponseCurrentSeq").value = ""

    if ($.trim($Statistic_Send_Control_Server.val()) == "Enable" 
        //-- Use Provisioning Upload ----------------------------{
        && $.trim($Statistic_Server_Ip.val()) != "" 
        && $.trim($Statistic_Server_Port.val()) != "") {
          ProvisioningUploadRequest(params)     
    }
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
    //$ChangeIPMode.removeAttr("disabled", "disabled"); 
    $ChangeIPMode.attr("disabled", "disabled"); 
    }
  }

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

  function checkSpace(str) { 
    if(str.search(/\s/) != -1) { 
      return true; 
    } else { 
      return false; 
    } 
  }

	//서버 리스트 바인딩
	function bindAddServerList($this) {
	 var bind =$('#tmplBackendServerList').tmpl().appendTo($this.closest('div[data-SiteType=2]').find('table'));
	 $('input[BackendIP]',bind).validate();
  	 $('input[BackendPort]',bind).validate();
	};
              
  UpdateChangeIPMode(isServerMode())
});

