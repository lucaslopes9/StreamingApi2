<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('RevVisualizar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAcesso);
$RevVisualizar = $VerificarAcesso[0];
 
if($RevVisualizar == 'S'){
	
$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['EnviarSMS']." (".$usuario.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"FormSMS form-horizontal\" action=\"javascript:MDouglasMS();\">

						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea rows=\"10\" class=\"form-control\" id=\"mensagem\" name=\"mensagem\"></textarea>
                            </div>
                        </div>
						
						<input type=\"hidden\" name=\"usuario\" id=\"usuario\" value=\"".$usuario."\" />
												
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"EMensagem btn btn-success\">".$_TRA['Enviar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>
<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.EMensagem").click(function() { 
 		
		var Data = $(".FormSMS").serialize();
		 		
		panel_refresh($(".FormSMS")); 
		
		$.post('EnviarSMSRev.php', Data, function(resposta) {
				setTimeout(panel_refresh($(".FormSMS")),500);
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>
   
<?php  
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>