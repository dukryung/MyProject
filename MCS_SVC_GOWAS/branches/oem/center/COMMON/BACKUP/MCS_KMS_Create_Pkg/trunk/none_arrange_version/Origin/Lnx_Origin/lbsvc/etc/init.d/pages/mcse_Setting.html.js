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
	$MCSS_Used = $("#MCSS_Used"),
	$MCSS_Buf_Size = $("#MCSS_Buf_Size"),
	$Encrypt_Mode = $("#Encrypt_Mode"),
	$Change_Client_Ip = $("#Change_Client_Ip");
	$Frontendsymbol = $("#Frontend input[Frontendsymbol]");
	$FrontendPort = $("#Frontend input[FrontendPort]");

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
	$MCSS_Buf_Size.validate();
	//$MCSS_Used.validate();
	$Encrypt_Mode.validate();
	$Change_Client_Ip.validate();
	$Frontendsymbol.validate();
	$FrontendPort.validate();

    
  if ($Statistic_Send_Control_Server.val() == "Disable") {
    $Statistic_Server_Ip.attr("disabled", "disabled"); 
    $Statistic_Server_Ip.val('');
    $Statistic_Server_Ip.validateRemove();
    $Statistic_Server_Port.attr("disabled", "disabled");
    $Statistic_Server_Port.val('');
    $Statistic_Server_Port.validateRemove();
    $Statistic_Send_Cycle.attr("disabled", "disabled");
    $Statistic_Send_Cycle.val('');
    $Statistic_Send_Cycle.validateRemove();
  }
//    $Statistic_Server_Ip.attr("disabled", "disabled"); 
 //   $Statistic_Server_Ip.val('');
  //$Statistic_Server_Ip.validateRemove();
//    $Statistic_Server_Port.attr("disabled", "disabled");
//    $Statistic_Server_Port.val('');
  //$Statistic_Server_Port.validateRemove();
//    $Statistic_Send_Cycle.attr("disabled", "disabled");
//    $Statistic_Send_Cycle.val('');
  //$Statistic_Send_Cycle.validateRemove();

  if ($MCSS_Used.val() == "Enable") {
    $MCSS_Buf_Size.attr("disabled","disabled");
    $MCSS_Buf_Size.val('');
    $MCSS_Buf_Size.validateRemove();
  }

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

	$($MCSS_Used).on('change',function(){
		var yn = $(this).val();
//		$MCSS_Buf_Size.val(yn == "Enable" ? "2097152" : "");
		if (yn =="Enable"){
			$MCSS_Buf_Size.attr("disabled" ,"disabled");
			$MCSS_Buf_Size.validateRemove();
		} else {
			$MCSS_Buf_Size.removeAttr("disabled"); 
			$MCSS_Buf_Size.validate();
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
          alert('MCS Mode 를 선택 후 Confirm 버튼을 클릭 하세요');
          return;
        }
        else {
          var $Backend = $($Frontdivs[i]).closest('div[data-SiteType=1]').find('div[data-SiteType=2]')
          if($Backend.attr('mcs_mode') != $($Frontdivs[i]).find("select[MCS_Mode]").val()) {
            alert('Confirm 버튼을 클릭 하세요');
            return;
          }
        }

        for(var j=0; j<$Backdivs.length; j++){
          var Backobj = { "LAN_interface": $($Backdivs[j]).find("select[LAN_interface]").val(),
            "BackendIP"	   : $($Backdivs[j]).find("input[BackendIP]").val(),
            "BackendPort"  : $($Backdivs[j]).find("input[BackendPort]").val()
          };
          backendarray.push(Backobj);
        };

        var Frontobj = { "Frontendsymbol" :  $($Frontdivs[i]).find("input[Frontendsymbol]").val(),
          "FrontendPort"	  :  $($Frontdivs[i]).find("input[FrontendPort]").val(),
          "MCSEMode"		  :  $($Frontdivs[i]).find("select[MCS_Mode]").val(),
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

        if(Frontobj.MCSEMode == "0") {
          alert('MCS 모드를 선택해 주세요');
          return;
        }
      };

		var params = {
			"Password": $Password.val(),
			"VerifyingPassword": $Verifying_Password.val(),
			"Maximum_ConnectionCount": $Maximum_ConnectionCount.val(),
			"Recv_Buf_Size": $Recv_Buf_Size.val(),
			"Send_Buf_Size": $Send_Buf_Size.val(),
			"Connection_Timeout": $Connection_Timeout.val(),
			"Client_Reconnect_Timeout": $Client_Reconnect_Timeout.val(),
			"Server_Reconnect_Timeout": $Server_Reconnect_Timeout.val(),
			"Limit_Size_Log_Storage": $Limit_Size_Log_Storage.val(),
			"Maxsize_Per_Logfile": $Maxsize_Per_Logfile.val(),
			"Logfile_Path": $Logfile_Path.val(),
			"Err_Logfile_Path": $Err_Logfile_Path.val(),
			"Statistic_Send_Control_Server": $Statistic_Send_Control_Server.val(),
			"Statistic_Collection_Cycle": $Statistic_Collection_Cycle.val(),
			"Statistic_Server_Ip": $Statistic_Server_Ip.val(),
			"Statistic_Server_Port": $Statistic_Server_Port.val(),
			"Statistic_Send_Cycle": $Statistic_Send_Cycle.val(),
			"MCSS_Used": $MCSS_Used.val(),
            "MCSS_Buf_Size": $MCSS_Buf_Size.val(),
			"Encrypt_Mode": $Encrypt_Mode.val(),
			"Change_Client_Ip": $Change_Client_Ip.val(),
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

          if ($SelectNumber > 0)  {
            if (isEmpty($Backend) == false) {
              if ($Backend.attr('mcs_mode') != $SelectNumber) {
                if (confirm('value가 삭제됩니다, 진행하시겠습니까?')) {
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
              alert('mcs 모드를 선택해 주세요');
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
		//$('#MCS_Mode', bind).validate();

		//바인딩한 데이터에 이벤트를 걸어준다.
		$('button[act]', bind).on('click', function () {
			var act = $(this).attr('act');

			if (act == 'btnFrontEndRemove') { // frontend 삭제
				$(this).closest('div[data-SiteType=1]').remove();
			}
			else if (act == 'btnFrontendConfirm') {// 컨펌 이벤트				
              var $Backend = $(this).closest('div').find('div[data-SiteType=2]')
              var $SelectNumber = Number($(this).closest('td').find('select option:selected').val())
                if ($SelectNumber > 0)  {
                  if (isEmpty($Backend) == false) {
                    if ($Backend.attr('mcs_mode') != $SelectNumber) {
                      if (confirm('value가 삭제됩니다, 진행하시겠습니까?')) {
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
					alert('mcs 모드를 선택해 주세요');
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
});

