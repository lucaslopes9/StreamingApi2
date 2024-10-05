<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspEditar');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspEditar = $VerificarAcesso[0];

if($ServidorcspEditar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$id = (isset($_POST['id'])) ? $_POST['id'] : '';

if( !empty($id) ){

$SQLCSP = "SELECT id, nome, url, porta, usuario, senha, protocolo, maxserver, block FROM painel WHERE id = :id";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->bindParam(':id', $id, PDO::PARAM_INT);
$SQLCSP->execute();
$LnCSP = $SQLCSP->fetch();

if($LnCSP['protocolo'] == "http"){
	$Eprotocolo = "<option value=\"http\">http</option><option value=\"https\">https</option>";
}else{
	$Eprotocolo = "<option value=\"https\">https</option><option value=\"http\">http</option>";
}

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." ".$LnCSP['nome']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarPainel form-horizontal\" action=\"javascript:MDouglasMS();\">
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['nome']."\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ipul']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarIPurl\" name=\"EditarIPurl\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['url']."\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarPorta\" name=\"EditarPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\" value=\"".$LnCSP['porta']."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarUsuario\" name=\"EditarUsuario\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['usuario']."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarSenha\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['senha']."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['protocolo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarProtocolo\" name=\"EditarProtocolo\">
                                    	".$Eprotocolo."
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['maxserver']."</label>
                            	<div class=\"col-md-9\">
									<input id=\"EditarMaxserver\" name=\"EditarMaxserver\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnCSP['maxserver']."\">
								</div>
                        </div>
						
						<input type=\"hidden\" name=\"EditarID\" id=\"EditarID\" value=\"".$id."\">
						
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

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".EditarPainel").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarPainel.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>
   
<?php  
}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>