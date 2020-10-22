$(document).ready(function () {
	//validate 와 val() 값을 동시에 사용하기때문에 selector 의 속도및 자원사용을 줄이기 위한 변수선언;
	//만약 이후 selector 의 이름이 변경 될 경우 아래 selector 의 id 만 변경해 줘도 무방함
	
  //-- Provisioning ----------------------------------------------------------------------{

  
  //-- Provisioning ----------------------------------------------------------------------}
	//페이지가 준비가 완료 되면 Frontend 의 이벤트를 걸어준다
	$('#wrapper button[act]').on('click', function (e) {
		e.preventDefault();
		var act = $(this).attr('act');
	
      if (act == "btnverconfirm") {
        var radiobuttonvalue = $(":input:radio[name=select_v]:checked").val();    

        if (radiobuttonvalue == "1") {
          if (document.getElementById("TR_SVCtype").value == "" && document.getElementById("TR_Scenariostate").value == "" ) {
            AuthTrial();
          } else if (document.getElementById("TR_SVCtype").value == "trial" && document.getElementById("TR_Scenariostate").value == "trial_certified"){
            var current_url = document.location.href;
            target_url = current_url.replace("versionselect", "login")
            $(location).attr('href',target_url);
          }      
        } else {
           if (document.getElementById("TR_SVCtype").value == "" && document.getElementById("TR_Scenariostate").value == "" ) {
            SVC_Page();
          } else if (document.getElementById("TR_SVCtype").value == "svc" && document.getElementById("TR_Scenariostate").value == "trial_update"){
            var current_url = document.location.href;
            target_url = current_url.replace("versionselect", "trial_update")
            $(location).attr('href',target_url);
          } 
        }
      }
    });
    function SVC_Page_Set_State() {
      var current_url = document.location.href
      target_url = current_url.replace("versionselect", "login_svc_set_state")
      $(location).attr('href',target_url);
    }

    function SVC_Page() {
      var current_url = document.location.href
      target_url = current_url.replace("versionselect", "login_svc")
      $(location).attr('href',target_url);
    }
  

function Trila_Setup_Request () {

    var send_json_data = {
    };

    $.ajax({
    async: false,
    url: "/trial_auth/",
    timeout:5000,
    retryCount: 0,
    retryLimit: 3,      
    type: "POST",
    dataType: "json",
    contentType: 'application/json; charset=UTF-8',
    data: JSON.stringify(send_json_data),
    complete: 
    function (response, textStatus) {
    var jsonObject = JSON.parse(response.responseText);
    
    if (response.status == "200") {
        if (jsonObject.code == "200") {
            document.getElementById("TR_ResponseCode").value = jsonObject.code;       
        } else {
            document.getElementById("TR_ResponseCode").value = jsonObject.code;   
        }
    }

    document.getElementById("TR_ResponseCode").value = jsonObject.code;   

    },
    error: 
    function(xml_request, text_status, error_thrown) {
    document.getElementById("TR_ResponseCode").value = "700";   
    },
  });
}

  function AuthTrial() {

    if (document.getElementById("DBAuthCode").value == "200") {

    } else if (document.getElementById("DBAuthCode").value == "000") {

    } else if (document.getElementById("DBAuthCode").value =="700") {

    } else if (document.getElementById("DBAuthCode").value == "652") {
      alert('서비스 기간 종료(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    } else if (document.getElementById("DBAuthCode").value == "653") {
      alert('종량제에 따른 서비스 제한(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else if (document.getElementById("DBAuthCode").value == "654") {
      alert('이미 사용한 Trial 입니다(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else if (document.getElementById("DBAuthCode").value == "655") {
      alert('Trial id 존재 하지 않음(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else  {
      alert('MCSE 연동 불가(Trial Version 사용 불가)');			
      alert('Service Version을 이용하세요.');
      return
    }

    Trila_Setup_Request()
    if (document.getElementById("TR_ResponseCode").value == "200") {
      alert('Trial service 인증 성공');  
      var current_url = document.location.href;
      target_url = current_url.replace("versionselect", "login")
      $(location).attr('href',target_url);  

    } else if (document.getElementById("TR_ResponseCode").value =="700") {
      alert('통신 장애');      
      return
    } else if (document.getElementById("TR_ResponseCode").value == "652") {
      alert('서비스 기간 종료(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    } else if (document.getElementById("TR_ResponseCode").value == "653") {
      alert('종량제에 따른 서비스 제한(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else if (document.getElementById("TR_ResponseCode").value == "654") {
      alert('이미 사용한 Trial 입니다(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else if (document.getElementById("TR_ResponseCode").value == "655") {
      alert('Trial id 존재 하지 않음(Trial Version 사용 불가)');
			alert('Service Version을 이용하세요.');
			document.getElementById('lg').submit();
			return      
    }  else  {
      alert('MCSE 연동 불가(Trial Version 사용 불가)');			
      alert('Service Version을 이용하세요.');
      return
    }

  };
});

