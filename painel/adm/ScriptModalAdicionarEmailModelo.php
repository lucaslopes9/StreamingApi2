<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('EmailModeloAdicionar');
$VerificarAcesso = VerificarAcesso('email_modelo', $ColunaAcesso);
$EmailModeloAdicionar = $VerificarAcesso[0];
 
if($EmailModeloAdicionar == 'S'){
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarModelo form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"tipo\" name=\"tipo\">
										<option value=\"Painel\">".$_TRA['Preferencia']."</option>
										<option value=\"Email\">".$_TRA['email']."</option>
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Assunto']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"assunto\" name=\"assunto\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                       
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea class=\"summernote\" id=\"mensagem\" name=\"mensagem\">
								[MEUEMAIL]: ".$_TRA['MEUEMAIL']."<br>
								[MEUNOME]: ".$_TRA['MEUNOME']."<br>
								[LGCLIENTE]: ".$_TRA['LGCLIENTE']."<br>
								[SNCLIENTE]: ".$_TRA['SNCLIENTE']."<br>
								[NMCLIENTE]: ".$_TRA['NMCLIENTE']."<br>
								[VCCLIENTE]: ".$_TRA['VCCLIENTE']."<br>
								[NOMEPERFIL]: ".$_TRA['NOMEPERFIL']."<br>
								[URLPERFIL]: ".$_TRA['URLPERFIL']."<br>
								[PORTAPERFIL]: ".$_TRA['PORTAPERFIL']."<br>
								[DESKEYS]: ".$_TRA['Deskeys']."<br>
								[URLPAINEL]: ".$_TRA['URLPAINEL']."<br>
								[NOMEPAINEL]: ".$_TRA['NOMEPAINEL']."
								</textarea>
                            </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarModelo btn btn-danger\">".$_TRA['Adicionar']."</button>
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
 		
		var tipo = $('.AdicionarModelo select[name="tipo"]').val();
		var assunto = $('.AdicionarModelo input[name="assunto"]').val();
		var mensagem = $('.AdicionarModelo textarea[name="mensagem"]').code();
		 		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarEmailModelo.php', {tipo:tipo, assunto:assunto, mensagem:mensagem}, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".AdicionarModelo select[name=tipo]").change(function(){
		
		var id = $(this).val();
		
		panel_refresh($(".FormEnviarCircular"));
		
		if(id == 'Painel'){
			setTimeout(panel_refresh($(".FormEnviarCircular")),500);
			$("#mensagem").code('[MEUEMAIL]: <?php echo $_TRA['MEUEMAIL']; ?><br>[MEUNOME]: <?php echo $_TRA['MEUNOME']; ?><br>[LGCLIENTE]: <?php echo $_TRA['LGCLIENTE']; ?><br>[SNCLIENTE]: <?php echo $_TRA['SNCLIENTE']; ?><br>[NMCLIENTE]: <?php echo $_TRA['NMCLIENTE']; ?><br>[VCCLIENTE]: <?php echo $_TRA['VCCLIENTE']; ?><br>[NOMEPERFIL]: <?php echo $_TRA['NOMEPERFIL']; ?><br>[URLPERFIL]: <?php echo $_TRA['URLPERFIL']; ?><br />[PORTAPERFIL]: <?php echo $_TRA['PORTAPERFIL']; ?><br>[DESKEYS]: <?php echo $_TRA['Deskeys']; ?><br>[URLPAINEL]: <?php echo $_TRA['URLPAINEL']; ?><br>[NOMEPAINEL]: <?php echo $_TRA['NOMEPAINEL']; ?>');
		}
		else{
			setTimeout(panel_refresh($(".FormEnviarCircular")),500);
			$("#mensagem").code('[MEUEMAIL]: <?php echo $_TRA['MEUEMAIL']; ?><br>[MEUNOME]: <?php echo $_TRA['MEUNOME']; ?><br>[URLPAINEL]: <?php echo $_TRA['URLPAINEL']; ?><br>[NOMEPAINEL]: <?php echo $_TRA['NOMEPAINEL']; ?>');
		}
				
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