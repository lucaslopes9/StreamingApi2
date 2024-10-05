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

$CadUser = InfoUser(2);
$SQLCSP = "SELECT id, CadUser, perfil, nome, url, porta, bloqueado FROM mascaraurl WHERE CadUser = :CadUser";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLCSP->execute();
$TotalMascara = count($SQLCSP->fetchAll());

//Verificar os Perfils do Usuário
$SQLPerfil = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
$SQLPerfil = $painel_user->prepare($SQLPerfil);
$SQLPerfil->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
$SQLPerfil->execute();
$LnPerfil = $SQLPerfil->fetch();
$valorcsp = $LnPerfil['perfil'];
$valorcsp = str_replace("][","],[",$valorcsp);

//Contar quantos perfils existe com os valores
$SQLMask = "SELECT id FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp)";
$SQLMask = $painel_geral->prepare($SQLMask);
$SQLMask->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR); 
$SQLMask->execute();
$TotalPerfil = count($SQLMask->fetchAll());
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['opcoes']; ?></li>
                    <li class="active"><?php echo $_TRA['mdp']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-external-link"></span> <?php echo $_TRA['mdp']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($TotalPerfil > $TotalMascara){
                                echo "<button type=\"button\" onclick=\"AdicionarPerfil();\" class=\"Adicionar btn btn-info active\">".$_TRA['Adicionar']."</button>";
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
                                        <th width="150"><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['Url']; ?></th>
                                        <th><?php echo $_TRA['Porta']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								$SQLCSP->execute();
								while($LnCSP = $SQLCSP->fetch()){
									
									$SQPerfil = "SELECT nome FROM perfil WHERE id = :id";
									$SQPerfil = $painel_geral->prepare($SQPerfil);
									$SQPerfil->bindParam(':id', $LnCSP['perfil'], PDO::PARAM_STR);
									$SQPerfil->execute();
									$LnPerfil = $SQPerfil->fetch();
										
										if($LnCSP['bloqueado'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
										
										echo "
                                        <tr>
                                        	<td>".$LnCSP['nome'].$status."</td>
                                        	<td>".$LnPerfil['nome']."</td>
                                        	<td>".$LnCSP['url']."</td>
											<td>".$LnCSP['porta']."</td>
                                       	    <td><div class=\"form-group\">";
								
									if($LnCSP['bloqueado'] == "S"){
										echo "<a class=\"label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\" onclick=\"DesBloquearPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\"></i></a>&nbsp;";
									}else{
										echo "<a class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\" onclick=\"BloquearPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}	
								
								echo "<a id=\"".$LnCSP['id']."\" class=\"label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\" onclick=\"EditarPerfil('".$LnCSP['id']."');\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								
								echo "<a onclick=\"DeletarPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								
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

		function DeletarPerfil(id, nome){
			 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarMaskPerfil';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}

		function BloquearPerfil(id, nome){ 
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearMaskPerfil';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		
		function DesBloquearPerfil(id, nome){ 
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearMaskPerfil';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}

		function EditarPerfil(id){  
 							
				panel_refresh($(".page-container")); 
				$.post('ScriptModalMaskPerfilEditar.php', {id: id}, function(resposta) {
				
				setTimeout(panel_refresh($(".page-container")),500);	
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
				
		}
		
		<?php
		if($TotalPerfil > $TotalMascara){
		?>
		function AdicionarPerfil(){ 
			
				panel_refresh($(".page-container")); 
 						
				$.post('ScriptModalMaskPerfilAdicionar.php', function(resposta) {
					
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