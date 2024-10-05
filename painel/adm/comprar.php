<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$AcessoUser = InfoUser(3);
$PrePagoSessao = empty($_SESSION['PrePago']) ? "N" : $_SESSION['PrePago'];

if( ($PrePagoSessao == "S") || ($AcessoUser == 3) || ($AcessoUser == 4) ){
?>

<style>
.panel-titulo {
  font-size: 14px;
  line-height: 30px;
  display: block;
  float: left;
  width:70%;
}
</style>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                    <li class="active"><?php echo $_TRA['Comprar']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-usd"></span> <?php echo $_TRA['Comprar']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default PanelStatus">
                                <div class="panel-heading ClassExibirRelatorio">
                                
                                <?php
								if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
								$SelecionarComprarNormal = SelecionarComprar('N');
								if(!empty($SelecionarComprarNormal)){
									
								$ValorCobrado = empty($_SESSION['ValorCobrado']) ? "" : $_SESSION['ValorCobrado'];
                       			$ValorCobradoCab = empty($_SESSION['ValorCobradoCab']) ? "" : $_SESSION['ValorCobradoCab'];	
									
								echo "
                                <div class=\"form-group panel-titulo\">
                            		<label class=\"col-md-3 control-label\">".$_TRA['seupla']."</label>
                           				<div class=\"col-md-9\">
                                			<select class=\"form-control select\" id=\"SelectPlan\" name=\"SelectPlan\">
                                    			<option value=\"0\">".$_TRA['seupla']."</option>";
												
												if( !empty($ValorCobrado) || !empty($ValorCobradoCab) ){
													echo "<option value=\"VC\">".$_TRA['paravc']."</option>";
												}
												
												echo "".$SelecionarComprarNormal."
                                			</select>
                            			</div>
                        		</div>
								";
								}
								}
								
								if($AcessoUser == 2){
								$SelecionarComprarPre = SelecionarComprar('P');
								if(!empty($SelecionarComprarPre)){
								echo "
                                <div class=\"form-group panel-titulo\">
                            		<label class=\"col-md-3 control-label\">".$_TRA['seupla']."</label>
                           				<div class=\"col-md-9\">
                                			<select class=\"form-control select\" id=\"SelectPlan\" name=\"SelectPlan\">
                                    			<option value=\"0\">".$_TRA['seupla']."</option>
												".$SelecionarComprarPre."
                                			</select>
                            			</div>
                        		</div>
								";
								}
								}
								?>

                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                
                            </div> <div id="StatusPlanos"></div>

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
        
        <script type='text/javascript'>  
		$(function(){
			$(".panel-titulo select[name=SelectPlan]").change(function(){
		
				var id = $(this).val();
				
				if(id != 0){
				panel_refresh($(".page-container")); 
				
				$.post('SelecionarPlano.php', {id: id}, function(resposta) {
					
					setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusPlanos").html('');
					$("#StatusPlanos").html(resposta);
				});
				}
				else{
					$("#StatusPlanos").html('');
				}
			});
		});
		</script>

    <!-- END SCRIPTS -->    
<?php
}
}else{
	echo Redirecionar('login.php');
}	
?>