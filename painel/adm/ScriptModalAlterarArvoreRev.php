<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if(ProtegePag() == true){
global $_TRA;

$CadUser = InfoUser(2);
		
$ColunaAdmin = array('RevVisualizar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminVisualizar = $VerificarAcesso[0];
 
if($AdminVisualizar == 'S'){
	
$camposMarcados = (isset($_POST['camposMarcados'])) ? $_POST['camposMarcados'] : '';
$string_array = implode("|", $camposMarcados);

echo "<div class=\"modal animated fadeIn\" id=\"AlterarArvore\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['ar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AltArvore form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['rev']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"RevendedorAll\" name=\"RevendedorAll\">
                                    	".SelecionarArvoreAll($CadUser)."
                                     </select>
                                 </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarAdicionar btn btn-warning\">".$_TRA['ar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
        
<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>

<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<!-- START TEMPLATE -->    
<?php include_once("js/settings".Idioma(2).".php"); ?>    
<script type="text/javascript" src="js/plugins.js"></script>        
<!-- END TEMPLATE -->

<script>
$("#AlterarArvore").modal("show");

$(function(){  
 $("button.SalvarAdicionar").click(function() { 
 		
		var rev = $('.AltArvore select[name="RevendedorAll"]').val();
		
		var i, camposMarcados, string_array;
		var status = 'arvore';
		string_array = '<?php echo $string_array; ?>';
		camposMarcados = string_array.split('|');
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarOpcoesRev.php', {camposMarcados: camposMarcados, rev: rev, status: status}, function(resposta) {
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