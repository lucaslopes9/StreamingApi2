<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$CadUser = InfoUser(2);
		
$ColunaAdmin = array('UserVisualizar');
$VerificarAcesso = VerificarAcesso('user', $ColunaAdmin);
$AdminVisualizar = $VerificarAcesso[0];
 
if($AdminVisualizar == 'S'){
	
$camposMarcados = (isset($_POST['camposMarcados'])) ? $_POST['camposMarcados'] : '';
$string_array = implode("|", $camposMarcados);

echo "<div class=\"modal animated fadeIn\" id=\"AlterarArvore\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['addv']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AltArvore form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['DataPremio']."</label>
                            <div class=\"col-md-9\">
								<div class=\"input-group date\">
                                	<input type=\"text\" id=\"dp-3\" name=\"EditarPremium\" class=\"form-control\" />
                                    <span class=\"input-group-addon\"><span class=\"glyphicon glyphicon-calendar\"></span></span>
                            	</div>
                            </div>
						</div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarAdicionar btn btn-warning\">".$_TRA['addv']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>

<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
        
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
<script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

<!-- START TEMPLATE -->   
<?php include_once("js/settings".Idioma(2).".php"); ?>     
<script type="text/javascript" src="js/plugins.js"></script>        
<!-- END TEMPLATE -->

<script>
$("#AlterarArvore").modal("show");

$(function(){  
 $("button.SalvarAdicionar").click(function() { 
 		
		var EditarPremium = $('.AltArvore input[name="EditarPremium"]').val();
				
		var i, camposMarcados, string_array;
		var status = 'vencimento';
		string_array = '<?php echo $string_array; ?>';
		camposMarcados = string_array.split('|');
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarOpcoesUser.php', {camposMarcados: camposMarcados, EditarPremium: EditarPremium, status: status}, function(resposta) {
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