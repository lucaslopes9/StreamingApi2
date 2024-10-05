<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

//Status do Servidor
$ColunaStatusServer = array('OpcoesStatusServer');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$AdminStatusServer = $VerificarStatusServer[0];

if($AdminStatusServer == 'S'){
	
	$SQLUrlT = "SELECT * FROM status_servidor";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->execute();
	$LnUrlT = $SQLUrlT->fetch();
	
	$status = empty($LnUrlT['status']) ? "N" : $LnUrlT['status'];
	$celular = empty($LnUrlT['celular']) ? "" : $LnUrlT['celular'];
	$email = empty($LnUrlT['email']) ? "" : $LnUrlT['email'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['AlertarOffline']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"ConfigTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
										
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['AlertarOffline']."?</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"Status\" name=\"Status\">";
									
									if($status == "S"){
										echo "<option value=\"S\">".$_TRA['Ativado']."</option>
										<option value=\"N\">".$_TRA['Desativado']."</option>";
									}
									else{
										echo "<option value=\"N\">".$_TRA['Desativado']."</option>
										<option value=\"S\">".$_TRA['Ativado']."</option>";										
									}
									
									echo "</select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Email\" name=\"Email\" type=\"text\" class=\"validate[required] form-control\" value=\"".$email."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Celular\" name=\"Celular\" type=\"text\" class=\"mask_phone_ext validate[required] form-control\" value=\"".$celular."\">
                            </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarConfigTeste btn btn-danger\">".$_TRA['configurar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<!-- START TEMPLATE -->  
<?php include_once("js/settings".Idioma(2).".php"); ?>   
<script type="text/javascript" src="js/plugins.js"></script>     
<!-- END TEMPLATE -->      


<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarConfigTeste").click(function() { 
 
 		var Data = $(".ConfigTeste").serialize();
		
		panel_refresh($(".ConfigTeste"));
				
		$.post('EnviarConfigStatusServer.php', Data, function(resposta) {
				setTimeout(panel_refresh($(".ConfigTeste")),500);
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