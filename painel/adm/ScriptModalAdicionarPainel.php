<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('ServidorcspAdicionar');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspAdicionar = $VerificarAcesso[0];
 
if($ServidorcspAdicionar == 'S'){
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarPainel form-horizontal\" action=\"javascript:MDouglasMS();\">
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ipul']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarIPurl\" name=\"EditarIPurl\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarPorta\" name=\"EditarPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarUsuario\" name=\"EditarUsuario\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarSenha\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['protocolo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarProtocolo\" name=\"EditarProtocolo\">
                                    	<option value=\"http\">http</option>
										<option value=\"https\">https</option>
                                     </select>
                                 </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['Adicionar']."</button>
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
 
		 var Data = $(".AdicionarPainel").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarPainel.php', Data, function(resposta) {
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