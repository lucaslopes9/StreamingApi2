<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('OpcoesGrupoAcesso');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesGrupoAcesso = $VerificarAcesso[0];
 
if($OpcoesGrupoAcesso == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
$CadUser = InfoUser(2);

$SQL = "SELECT nome FROM grupodeacesso WHERE id = :id AND CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':id', $id, PDO::PARAM_INT);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();

$nome = empty($Ln['nome']) ? "" : $Ln['nome'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." (".$nome.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarTempoTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                       
                         <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            	<div class=\"col-md-9\">
                                	<input type=\"text\" name=\"EditarNome\" id=\"EditarNome\" class=\"form-control\" value=\"".$nome."\"/>
                                </div>
                        </div>
						
						<input type=\"hidden\" id=\"id\" name=\"id\" value=\"".$id."\">

						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"BotaoTempoTeste btn btn-danger\">".$_TRA['editar']."</button>
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
 $("button.BotaoTempoTeste").click(function() { 
 
		 var Data = $(".EditarTempoTeste").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarGrupodeAcesso.php', Data, function(resposta) {
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