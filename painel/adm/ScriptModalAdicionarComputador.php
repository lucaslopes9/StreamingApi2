<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesLiberarComputador');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesLiberarComputador = $VerificarAcesso[0];

if($OpcoesLiberarComputador == 'S'){
	
$CadUser = InfoUser(2);
$SQLCel = "SELECT celular FROM ".SelectTabela()." WHERE usuario = :usuario";
$SQLCel = $painel_user->prepare($SQLCel);
$SQLCel->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
$SQLCel->execute();
$LnCel = $SQLCel->fetch();
$celular = $LnCel['celular'];

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['lb']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated StatusLiberarComputador\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarLiberarComputador form-horizontal\" action=\"javascript:MDouglasMS();\">
                     
                        <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            	<div class=\"col-md-9\"> 
									<input id=\"Celular\" value=\"".$celular."\" name=\"Celular\" type=\"text\" class=\"form-control\" disabled=\"disabled\">
                                </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Computador']."</label>
                            <div class=\"col-md-9\">";
							
							$Hostname = getenv('USERNAME');	
							$gethostbyaddr = gethostbyaddr($_SERVER['REMOTE_ADDR']);
							
							echo "<label class=\"check\"><input type=\"checkbox\" class=\"icheckbox\" checked=\"checked\" disabled=\"disabled\"/> ".$Hostname." (".$gethostbyaddr.") </label>";
							
                            echo "</div>
                        </div>
						
						 <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ip']."</label>
                            <div class=\"col-md-9\">";
														
							echo "<label class=\"check\"><input type=\"checkbox\" class=\"icheckbox\" checked=\"checked\" disabled=\"disabled\"/> ".$_SERVER['REMOTE_ADDR']."</label>";
							
                            echo "</div>
                        </div>

						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <span id=\"StatusLiberarBtao\"><button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['Liberar']."</button></span>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>
<script type='text/javascript' src='js/plugins.js'></script>

<!-- START TEMPLATE -->    
<?php include_once("js/settings".Idioma(2).".php"); ?>     
<script type="text/javascript" src="js/plugins.js"></script>      
<!-- END TEMPLATE -->

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".AdicionarLiberarComputador").serialize();
				
		panel_refresh($(".AdicionarLiberarComputador")); 
				
		$.post('EnviarLiberarComputador.php', Data, function(resposta) {
				setTimeout(panel_refresh($(".AdicionarLiberarComputador")),500);
				$(".StatusLiberarComputador").html('');
				$(".StatusLiberarComputador").append(resposta);
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