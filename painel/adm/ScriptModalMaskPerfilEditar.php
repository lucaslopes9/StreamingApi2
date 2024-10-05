<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesMascaraURL');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesMascaraURL = $VerificarAcesso[0];

if($OpcoesMascaraURL == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
$CadUser = InfoUser(2);

$SQLMask = "SELECT perfil, nome, url, porta FROM mascaraurl WHERE CadUser = :CadUser AND id = :id";
$SQLMask = $painel_geral->prepare($SQLMask);
$SQLMask->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLMask->bindParam(':id', $id, PDO::PARAM_STR);
$SQLMask->execute();
$LnMask = $SQLMask->fetch();

$perfil = $LnMask['perfil'];
$nome = $LnMask['nome'];
$url = $LnMask['url'];
$porta = $LnMask['porta'];

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarPerfil form-horizontal\" action=\"javascript:MDouglasMS();\">
                     
                        <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"PerfilCSP\" name=\"PerfilCSP\">";
										
										echo PerfilSelectMascaraEdit($CadUser, $id); 
										
										echo "
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Nome\" name=\"Nome\" type=\"text\" class=\"validate[required] form-control\" value=\"".$nome."\">
                            </div>
                        </div>

						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Url']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Url\" name=\"Url\" type=\"text\" class=\"validate[required] form-control\" value=\"".$url."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"Porta\" name=\"Porta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\" value=\"".$porta."\">
                            </div>
                        </div>
						
						<input type=\"hidden\" id=\"id\" name=\"id\" value=\"".$id."\">
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['alterar']."</button>
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
		
		var Data = $(".AdicionarPerfil").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarMaskPerfil.php', Data, function(resposta) {
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