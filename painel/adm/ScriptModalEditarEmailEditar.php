<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('OpcoesEmailTeste');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesEmailTeste = $VerificarAcesso[0];

if($OpcoesEmailTeste == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
$CadUser = InfoUser(2);
$SQL = "SELECT * FROM email_teste WHERE CadUser = :CadUser AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->bindParam(':id', $id, PDO::PARAM_INT);
$SQL->execute();
$Ln = $SQL->fetch();
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." (".$Ln['email'].")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarEmail form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EmailEmail\" name=\"EmailEmail\" value=\"".$Ln['email']."\" type=\"text\" class=\"validate[required,custom[email]] form-control\">
                            </div>
                        </div>
						
						<input type=\"hidden\" id=\"EmailID\" name=\"EmailID\" value=\"".$id."\">

						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"EditarEmail btn btn-danger\">".$_TRA['editar']."</button>
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

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.EditarEmail").click(function() { 
 
		var Data = $(".EditarEmail").serialize();
		
		panel_refresh($(".EditarEmail"));
		
		$.post('EnviarEmailEditarTeste.php', Data, function(resposta) {
			
				setTimeout(panel_refresh($(".EditarEmail")),500);
			
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