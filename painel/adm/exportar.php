<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesExportar');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesExportar = $VerificarAcesso[0];

if($OpcoesExportar == 'S'){
$CadUser = InfoUser(2);
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['opcoes']; ?></li>
                    <li class="active"><?php echo $_TRA['Exportar']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-level-up"></span> <?php echo $_TRA['Exportar']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="EnviarExpImp panel panel-success">
                                <div class="panel-heading">
                                    <h3 class="panel-title">
                                	<select class="form-control select" id="RevendedorAll" name="RevendedorAll">
                                    	<option value="Todos"><?php echo $_TRA['Todos']; ?></option>
                                    	<?php echo SelecionarArvoreAll($CadUser); ?>
                                     </select>
                                    </h3>
                                </div>
                                <div class="panel-body">
                                
                                <?php
								echo "
								<div class=\"form-group\">
                            	<div class=\"col-md-9\">
							    	<textarea class=\"form-control\" id=\"mensagem\" name=\"mensagem\" rows=\"10\"></textarea>
                            	</div>
                       		    </div>
								";
								
								?>
                                    
                                </div>      
                                <div class="panel-footer">
                                    <button class="ExpImp btn btn-success pull-right"><?php echo $_TRA['Exportar']; ?></button>
                                </div>                            
                            </div>
                            
                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>     
        
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->   
        
        <script>
		$(function(){  
 			$("button.ExpImp").click(function() { 
			 		
				var usuario = $('.EnviarExpImp select[name="RevendedorAll"]').val();
			 		
				var panel = $('.EnviarExpImp');
       		    panel_refresh(panel);
		
				$.post('EnviarExportar.php', {usuario: usuario}, function(resposta) {
					
					setTimeout(function(){
            			panel_refresh(panel);
        			},500);	
					
					var n = resposta.search("<LimparScript><script>");
					
					if(n == 0){			
						$("#StatusModal").html('');
						$("#StatusGeral").append(resposta);
					}
					else{
						$(".EnviarExpImp textarea[name='mensagem']").val('');
						$(".EnviarExpImp textarea[name='mensagem']").val(resposta.trim());
					}
					
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