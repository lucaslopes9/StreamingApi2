<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$AcessoUser = InfoUser(3);
if( ($AcessoUser == 1) || ($AcessoUser == 2) ){

$CadUser = InfoUser(2);
	
$SQL = "SELECT whatsapp FROM rede_social WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();
$whatsapp = $Ln['whatsapp'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">Configurar WhatsApp</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarCaptcha form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">WhatsApp</label>
                            	<div class=\"col-md-9\">
                                	<input type=\"text\" name=\"RedeSocial\" id=\"RedeSocial\" class=\"form-control\" value=\"".$whatsapp."\"/>
                                </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"SalvarCaptcha btn btn-danger\">Salvar</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarCaptcha").click(function() { 
 
		 var Data = $(".AdicionarCaptcha").serialize();
		
		panel_refresh($(".AdicionarCaptcha"));
		
		$.post('EnviarConfigurarWhatsApp.php', Data, function(resposta) {
			
				setTimeout(panel_refresh($(".AdicionarCaptcha")),500);
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