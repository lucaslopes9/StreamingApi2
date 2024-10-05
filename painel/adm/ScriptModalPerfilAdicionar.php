<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PerfilAdicionar');
$VerificarAcesso = VerificarAcesso('perfil', $ColunaAcesso);
$PerfilAdicionar = $VerificarAcesso[0];
 
if($PerfilAdicionar == 'S'){

$SQLPainel = "SELECT id, nome FROM painel";
$SQLPainel = $painel_geral->prepare($SQLPainel);
$SQLPainel->execute();
$TotalPainel = count($SQLPainel->fetchAll());

$SQLImagem = "SELECT id, nome, img FROM perfil_icone";
$SQLImagem = $painel_geral->prepare($SQLImagem);
$SQLImagem->execute();
$TotalImagem = count($SQLImagem->fetchAll());

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['addperfil']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarPerfil form-horizontal\" action=\"javascript:MDouglasMS();\">
                        
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['SCSP']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarCSP\" name=\"EditarCSP\">";
										
									if($TotalPainel > 0){
									$SQLPainel->execute();
									while($LnPainel = $SQLPainel->fetch()){
                                    echo "<option value=\"".$LnPainel['id']."\">".$LnPainel['nome']."</option>";
									}
									}
									else{
										echo "<option value=\"0\">".$_TRA['SSCSP']."</option>";
									}
										
										echo "
                                     </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarTipo\" name=\"EditarTipo\">
                                    	<option value=\"SAT\">".$_TRA['satelite']."</option>
										<option value=\"CAB\">".$_TRA['cabo']."</option>
                                    </select>
                                </div>
                        </div>
						
                        <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Imagem']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarImagem\" name=\"EditarImagem\">";

									if($TotalImagem > 0){
										$SQLImagem->execute();
										while($LnImagem = $SQLImagem->fetch()){
										$FotoPerfil = FotoPerfil($LnImagem['img']);
										echo "<option data-content='<img src=\"".$FotoPerfil."\" height=\"16\" width=\"16\"><span style=\"padding:0px 0px 0px 10px;\">".ucfirst($LnImagem['nome'])."</span>' value=\"".$LnImagem['id']."\"></option>";
										}
									}
									else{
										echo "<option value=\"0\">".$_TRA['SImagem']."</option>";
									}
										
										echo "
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcsp']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarValorCSP\" name=\"EditarValorCSP\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Url']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarUrl\" name=\"EditarUrl\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Porta']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarPorta\" name=\"EditarPorta\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\">
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
		
		$.post('EnviarAdicionarPerfil.php', Data, function(resposta) {
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