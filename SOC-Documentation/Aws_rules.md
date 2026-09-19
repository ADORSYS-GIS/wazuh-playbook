 ```
 <group name="amazon,aws,">
	<!-- AWS Root console login - CRITICAL -->
	<rule id="900300" level="15">
		<if_group>aws_cloudtrail</if_group>
		<match>ConsoleLogin</match>
		<field name="userIdentity.type">Root</field>
		<description>AWS: Root account console login detected</description>
		<mitre>
			<id>T1078</id>
		</mitre>
	</rule>

	<!-- Multiple failed AWS console logins from same source -->
	<rule id="900301" level="12" frequency="5" timeframe="300">
		<if_group>aws_cloudtrail</if_group>
		<match>ConsoleLogin</match>
		<field name="responseElements.ConsoleLogin">Failure</field>
		<if_matched_sid>900101</if_matched_sid>
		<same_srcip />
		<description>AWS: Multiple failed console login attempts from same IP</description>
		<mitre>
			<id>T1110</id>
		</mitre>
	</rule>

	<!-- Successful login after multiple failures -->
	<rule id="900302" level="13">
		<if_group>aws_cloudtrail</if_group>
		<match>ConsoleLogin</match>
		<field name="responseElements.ConsoleLogin">Success</field>
		<if_matched_sid>900101</if_matched_sid>
		<same_srcip />
		<description>AWS: Successful console login after multiple failures</description>
		<mitre>
			<id>T1078</id>
			<id>T1110</id>
		</mitre>
	</rule>

	<!-- New IAM user created -->
	<rule id="900310" level="12">
		<if_group>aws_cloudtrail</if_group>
		<match>CreateUser</match>
		<description>AWS IAM: New IAM user created</description>
		<mitre>
			<id>T1136</id>
		</mitre>
	</rule>

	<!-- IAM access key creation -->
	<rule id="900311" level="13">
		<if_group>aws_cloudtrail</if_group>
		<match>CreateAccessKey</match>
		<description>AWS IAM: New access key created</description>
		<mitre>
			<id>T1552</id>
		</mitre>
	</rule>

	<!-- Policy attached / modified -->
	<!--<rule id="900312" level="13">-->
	<!--	<if_group>aws_cloudtrail</if_group>-->
	<!--	<regex>Attach(User|Role|Group)Policy|Put(User|Role|Group)Policy</regex>-->
	<!--	<description>AWS IAM: Permissions or policies modified</description>-->
	<!--	<mitre>-->
	<!--		<id>T1484</id>-->
	<!--	</mitre>-->
	<!--</rule>-->

	<!-- AssumeRole trust policy changed -->
	<rule id="900313" level="14">
		<if_group>aws_cloudtrail</if_group>
		<match>UpdateAssumeRolePolicy</match>
		<description>AWS IAM: AssumeRole trust policy modified</description>
		<mitre>
			<id>T1098</id>
		</mitre>
	</rule>

	<!-- EC2 key pair created/imported -->
	<rule id="900320" level="12">
		<if_group>aws_cloudtrail</if_group>
		<regex>CreateKeyPair|ImportKeyPair</regex>
		<description>AWS EC2: Key pair created or imported</description>
	</rule>

	<!-- EC2 key pair deleted -->
	<rule id="900321" level="11">
		<if_group>aws_cloudtrail</if_group>
		<match>DeleteKeyPair</match>
		<description>AWS EC2: Key pair deleted</description>
	</rule>

	<!-- Security group modified -->
	<rule id="900330" level="11">
		<if_group>aws_cloudtrail</if_group>
		<regex>AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress|RevokeSecurityGroupIngress|RevokeSecurityGroupEgress</regex>
		<description>AWS EC2: Security group modified</description>
	</rule>

	<!-- Security group opened to world -->
	<rule id="900331" level="14">
		<if_group>aws_cloudtrail</if_group>
		<regex>AuthorizeSecurityGroupIngress</regex>
		<match>0.0.0.0/0</match>
		<description>AWS EC2: Security group opened to world</description>
	</rule>

	<!-- S3 bucket ACL / policy modified -->
	<rule id="900340" level="11">
		<if_group>aws_cloudtrail</if_group>
		<regex>PutBucketAcl|PutBucketPolicy|PutBucketPublicAccessBlock</regex>
		<description>AWS S3: Bucket ACL or policy modified</description>
	</rule>

	<!-- S3 bucket made public -->
	<rule id="900341" level="14">
		<if_group>aws_cloudtrail</if_group>
		<regex>PutBucketAcl|PutBucketPolicy</regex>
		<regex>AllUsers|AuthenticatedUsers</regex>
		<description>AWS S3: Bucket made publicly accessible</description>
	</rule>

	<!-- CloudTrail logging stopped -->
	<rule id="900350" level="15">
		<if_group>aws_cloudtrail</if_group>
		<match>StopLogging</match>
		<description>AWS CloudTrail: Logging stopped</description>
	</rule>

	<!-- CloudTrail trail deleted -->
	<rule id="900351" level="15">
		<if_group>aws_cloudtrail</if_group>
		<match>DeleteTrail</match>
		<description>AWS CloudTrail: Trail deleted</description>
	</rule>

	<!-- CloudTrail configuration modified -->
	<rule id="900352" level="14">
		<if_group>aws_cloudtrail</if_group>
		<match>UpdateTrail</match>
		<description>AWS CloudTrail: Trail configuration modified</description>
	</rule>

	<!-- KMS key disabled or deleted -->
	<rule id="900360" level="14">
		<if_group>aws_cloudtrail</if_group>
		<regex>DisableKey|ScheduleKeyDeletion</regex>
		<description>AWS KMS: Key disabled or scheduled for deletion</description>
	</rule>

	<!-- New KMS grant -->
	<rule id="900361" level="12">
		<if_group>aws_cloudtrail</if_group>
		<match>CreateGrant</match>
		<description>AWS KMS: New grant created</description>
	</rule>
</group>
