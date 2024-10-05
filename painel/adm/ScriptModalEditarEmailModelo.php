<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('EmailModeloEditar');
$VerificarAcesso = VerificarAcesso('email_modelo', $ColunaAcesso);
$EmailModeloEditar = $VerificarAcesso[0];
 
if($EmailModeloEditar == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

$CadUser = InfoUser(2);
$SQL = "SELECT tipo, assunto, mensagem, bloqueado FROM email_modelo WHERE CadUser = :CadUser AND id = :id";
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
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarModelo form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"tipo\" name=\"tipo\">";
								
								if($Ln['tipo'] == "Painel"){
								  echo "<option value=\"Painel\">".$_TRA['Preferencia']."</option><option value=\"Email\">".$_TRA['email']."</option>";
								}
								else{
								  echo "<option value=\"Email\">".$_TRA['email']."</option><option value=\"Painel\">".$_TRA['Preferencia']."</option>";
								}
									echo "</select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Assunto']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"assunto\" name=\"assunto\" type=\"text\" value=\"".$Ln['assunto']."\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                       
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea class=\"summernote\" id=\"mensagem\" name=\"mensagem\">".$Ln['mensagem']."</textarea>
                            </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarModelo btn btn-danger\">".$_TRA['alterar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type="text/javascript" src="js/plugins/summernote/summernote<?php echo Idioma(2); ?>.js"></script>
<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarModelo").click(function() { 
 		
		var tipo = $('.EditarModelo select[name="tipo"]').val();
		var assunto = $('.EditarModelo input[name="assunto"]').val();
		var mensagem = $('.EditarModelo textarea[name="mensagem"]').code();
		var id = '<?php echo $id; ?>';
		 		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarEmailModelo.php', {tipo:tipo, assunto:assunto, mensagem:mensagem, id:id}, function(resposta) {
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