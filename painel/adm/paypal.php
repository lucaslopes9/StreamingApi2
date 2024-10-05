<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PagamentoPayPal');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoPayPal = $VerificarAcesso[0];

if($PagamentoPayPal == 'S'){
	
$CadUser = InfoUser(2);

$SQL = "SELECT id, email, senha, bloqueado FROM contapaypal WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();
$Total = count($SQL->fetchAll());
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['Pagamentos']; ?></li>
                    <li><?php echo $_TRA['FormadePagamento']; ?></li>
                    <li class="active"><?php echo $_TRA['PayPal']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-chevron-right"></span> <?php echo $_TRA['PayPal']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-default">
                                <div class="panel-heading">
                                <?php
								if($Total == 0){
                                	echo "<button type=\"button\" onclick=\"AdicionarForma();\" class=\"btn btn-info active\">".$_TRA['Adicionar']."</button>";
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
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="150"><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								$SQL->execute();
								while($Ln = $SQL->fetch()){
									
								if($Ln['bloqueado'] == "S"){
									$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
								}else{
									$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloqueado']."\">".$_TRA['desbloqueado'][0]."</span>";
								}

										echo "
                                        <tr>
											<td>".$Ln['email'].$status."</td>
                                        	<td>".$Ln['senha']."</td>
                                       	    <td><div class=\"form-group\">";
								
								if($Ln['bloqueado'] == "S"){
									echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\" Onclick=\"DesbloquearMetodo('".$Ln['id']."')\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
								}else{
									echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" Onclick=\"BloquearMetodo('".$Ln['id']."')\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
								}
											
								echo "<a class=\"label label-info\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['info']."\" onclick=\"InformacoesForma('".$Ln['id']."');\"><i class=\"fa fa-info-circle\"></i></a>&nbsp;";
								
								echo "<a class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\" onclick=\"EditarForma('".$Ln['id']."');\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								
								echo "<a onclick=\"DeletarForma('".$Ln['id']."','".$Ln['email']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								
									echo "</div>
										</td>
                                      </tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?> 
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>
		function BloquearMetodo(id){ 
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo str_replace(":","",$_TRA['tcqdba']); ?>?';
				var tipo = 'danger';
				var url = 'EnviarBloquearPaypal';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		function DesbloquearMetodo(id){ 
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo str_replace(":","",$_TRA['tcqdda']); ?>?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearPayPal';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		 
		function InformacoesForma(id){
							
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalInfoFormaPayPal.php', {id: id}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		 
		function DeletarForma(id, email){
			 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+email+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarFormaPayPal';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}

		function EditarForma(id){  
 							
				panel_refresh($(".page-container")); 
				$.post('ScriptModalFormaPayPalEditar.php', {id: id}, function(resposta) {
				
				setTimeout(panel_refresh($(".page-container")),500);	
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		if($Total == 0){
		?>
		function AdicionarForma(){ 
			
				panel_refresh($(".page-container")); 
 						
				$.post('ScriptModalFormaPayPal.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		?>
		</script>

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>